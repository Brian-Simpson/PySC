"""
Tenable .audit comment synchronizer

Synchronizes commented controls from a BASE audit file
to a TARGET audit file.

Matching logic:

- Description must be >= 80% similar
- Reference must match exactly
- Value Type must match exactly
- Value Data must match exactly
- Check Type must match exactly

Type and PowerShell are ignored for matching because
they are modified during conversion.
"""

from email.mime import base
from os import path
import pathlib
import datetime
import shutil
import re
import sys
import difflib
import pandas as pd

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from pysc_block_parser import parse_blocks

from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
    MofNCompleteColumn
)

KNOWN_SHARED_PRIVILEGES = {

    "privilege|senetworklogonright",
    "privilege|sedenynetworklogonright",
    "privilege|sedenyremoteinteractivelogonright",
    "privilege|setcbprivilege",

}

DATE_STR = datetime.datetime.now().strftime("%Y%m%d")


MATCH_THRESHOLD = 60

MIN_THRESHOLDS = {
    "description": 65,
    "reference": 90,
    "value_type": 0,
    "value_data": 85,
    "check_type": 0,
    "powershell_args": 55,
}

WEIGHTS = {
    "description": 15,
    "reference": 15,
    "value_type": 5,
    "value_data": 15,
    "check_type": 5,
    "powershell_args": 45,
}

# Global debug toggle. Set to True to enable verbose debugging output.
DEBUG = False

def dbg_print(*args, **kwargs):
    if DEBUG:
        print(*args, **kwargs)

# ============================================================
# FIELD EXTRACTION
# ============================================================

def get_field(block_text, field_name):

    pattern = (
        rf'^\s*#?\s*{re.escape(field_name)}\s*:\s*(.*?)\s*$'
    )

    m = re.search(
        pattern,
        block_text,
        flags=re.IGNORECASE | re.MULTILINE
    )

    if not m:
        return ""

    if field_name.lower() == "reference":

        value = m.group(1).strip()

        if value.upper().startswith("SEE_ALSO"):
            return ""

        return value.strip('"')

    return m.group(1).strip().strip('"')



# ============================================================
# NORMALIZATION
# ============================================================

STOP_WORDS = {
    "ensure",
    "configure",
    "configured",
    "setting",
    "settings",
    "policy",
    "is",
    "are",
    "set",
    "to",
    "the",
    "a",
    "an",
    "of",
    "and",
    "or",
    "be",
    "being",
    "enabled",
    "disabled",
    "checked",
    "not",
    "only",
    "server",
    "client",
    "mssrv",
    "ms",
    "dc",
    "l1",
    "l2",
}


def normalize_description(text):

    if not text:
        return ""

    text = text.lower()

    #
    # Remove benchmark prefixes
    #
    text = re.sub(
        r"^\d+(?:\.\d+)*\s*-\s*",
        "",
        text
    )

    #
    # Remove AC - MSSRV -, CM - MSSRV -, etc.
    #
    text = re.sub(
        r"^[a-z]{2,3}\s*-\s*mssrv(?:\.dc)?\s*-\s*",
        "",
        text
    )

    #
    # Remove (L1), (L2), (DC only), (MS only), etc.
    #
    text = re.sub(
        r"\([^)]*\)",
        " ",
        text
    )

    #
    # Remove quotes
    #
    text = text.replace('"', " ")
    text = text.replace("'", " ")

    #
    # Replace punctuation with spaces
    #
    text = re.sub(
        r"[^a-z0-9]+",
        " ",
        text
    )

    #
    # Split into words
    #
    words = []

    for word in text.split():

        if word in STOP_WORDS:
            continue

        words.append(word)

    #
    # Remove duplicates while preserving order
    #
    seen = set()
    unique_words = []

    for word in words:

        if word in seen:
            continue

        seen.add(word)
        unique_words.append(word)

    #
    # Sort words so word order doesn't matter
    #
    unique_words = sorted(unique_words)

    return " ".join(unique_words)

def normalize_reference(reference):

    reference = reference.strip().strip('"')

    if "|" in reference:
        reference = reference.split("|", 1)[1]

    reference = reference.upper()

    reference = re.sub(
        r"\([A-Z]\)",
        "",
        reference
    )

    return " ".join(reference.split())


def normalize_value_data(value_data):

    value_data = (
        value_data
        .replace('"', '')
        .replace("'", '')
        .strip()
    )

    value_data = re.sub(
        r"\s*\|\|\s*",
        "||",
        value_data
    )

    value_data = " ".join(
        value_data.split()
    )

    value_data = re.sub(
        r"success\s*(?:and|,)\s*failure",
        "success failure",
        value_data,
        flags=re.IGNORECASE
    )

    return value_data

def normalize_registry_key(key):

    key = key.lower()

    #
    # HKCU cleanup
    #

    key = re.sub(
        r"registry::hkey_users\\s-1-5-[^\\]+\*?\\",
        r"hkcu:\\",
        key,
        flags=re.IGNORECASE
    )

    key = re.sub(
        r"registry::hkey_users\\s-1-5-21\*",
        r"hkcu:",
        key,
        flags=re.IGNORECASE
    )

    #
    # Netlogon
    #

    key = key.replace(
        "\\netlogon\\parameter|",
        "\\netlogon\\parameters|"
    )

    key = key.replace(
        "\\parameters\\|",
        "\\parameters|"
    )

    #
    # Firewall corruption
    #

    key = key.replace(
        "\\software\\policies\\microsoft\\windowsfirewall\\publicprofile\\loggin\\software\\policies\\microsoft\\windowsfirewall\\publicprofile\\logging",
        "\\software\\policies\\microsoft\\windowsfirewall\\publicprofile\\logging"
    )

    key = key.replace(
        "\\|",
        "|"
    )

    #
    # HKCU paths missing hive prefix
    #

    if (
        key.startswith("registry|software\\")
        and "|software\\" in key
    ):
        key = key.replace(
            "registry|software\\",
            "registry|hkcu:\\software\\",
            1
        )

    return key

def normalize_powershell(ps):

    if not ps:
        return ""

    ps = ps.replace("&amp;amp;amp;gt;", "&gt;")
    ps = ps.replace("&amp;amp;amp;amp;gt;", "&gt;")
    ps = ps.strip()

    lower_ps = ps.lower()

    #
    # INSTALLED WINDOWS
    #

    if "productname" in lower_ps:

        return (
            "registry|"
            "hklm:\\software\\microsoft\\windows nt\\currentversion"
            "|productname"
        )

    #
    # USER RIGHTS
    #

    m = re.search(
        r"se[a-z]+(?:privilege|right)",
        lower_ps,
        re.IGNORECASE
    )

    if m:

        # print(
        #     "USER RIGHT DETECTED:",
        #     m.group(0)
        # )

        return (
            f"privilege|"
            f"{m.group(0).lower()}"
        )

    #
    # NET ACCOUNTS
    #

    if "net accounts" in lower_ps:

        if "minimum password age" in lower_ps:
            return "net accounts minimum password age"

        if "maximum password age" in lower_ps:
            return "net accounts maximum password age"

        if "maximum password" in lower_ps:
            return "net accounts maximum password age"

        if "minimum password length" in lower_ps:
            return "net accounts minimum password length"

        if "password length" in lower_ps:
            return "net accounts minimum password length"

        if "password history" in lower_ps:
            return "net accounts password history"

        if "lockout threshold" in lower_ps:
            return "net accounts lockout threshold"

        if "invalid logon attempts" in lower_ps:
            return "net accounts lockout threshold"

        if re.search(
            r"net accounts.*\\d\{1,3\}",
            lower_ps
        ):
            return "net accounts lockout threshold"

        if "lockout duration" in lower_ps:
            return "net accounts lockout duration"

        if "observation window" in lower_ps:
            return "net accounts lockout observation window"

        if "lockout observation" in lower_ps:
            return "net accounts lockout observation window"

        if "reset lockout" in lower_ps:
            return "net accounts lockout observation window"

        m = re.search(
            r"net accounts.*?(?:select-string|match)\s+'([^']+)'",
            lower_ps,
            re.IGNORECASE | re.DOTALL
        )

        if m:
            return (
                f"net accounts "
                f"{m.group(1).lower()}"
            )

        return "net accounts"

    #
    # AUDITPOL
    #

    m = re.search(
        r"/subcategory:'([^']+)'",
        ps,
        re.IGNORECASE
    )

    if m:
        return f"auditpol.exe {m.group(1).lower()}"

    if lower_ps.startswith("auditpol.exe"):
        return lower_ps

    #
    # LOCAL ACCOUNTS
    #

    if "-501$" in ps:
        return "account|guest"

    if "-500$" in ps:
        return "account|administrator"

    #
    # WINDOWS FEATURES
    #

    SERVICE_NAMES = {
        "wins",
        "mpssvc",
        "eventlog",
        "samss",
        "lanmanserver",
        "lanmanworkstation",
        "termservice",
        "usosvc",
        "bfe",
        "winrm",
        "ir_agent",
        "sentinelagent",
        "sentinelhelperservice",
        "sentinelstaticengine",
        "logprocessorservice",
        "wpnservice",
    }

    m = re.search(
        r"\.name\s+-eq\s+'([^']+)'",
        ps,
        re.IGNORECASE
    )

    if m:

        name = m.group(1).lower()

        if name in SERVICE_NAMES:
            return f"service|{name}"

        return f"feature|{name}"

    m = re.search(
        r"\.name\s+-like\s+'([^']+)'",
        ps,
        re.IGNORECASE
    )

    if m:

        name = m.group(1).lower().replace("*", "")

        if name in SERVICE_NAMES:
            return f"service|{name}"

        return f"feature|{name}"

    #
    # WINDOWS FEATURE CHECKS
    #

    m = re.search(
        r"get-windowsfeature.*?name\s+'([^']+)'",
        ps,
        re.IGNORECASE
    )

    if m:
        return f"feature|{m.group(1).lower()}"

    #
    # SERVICES
    #

    m = re.search(
        r"get-service\s+-name\s+'([^']+)'",
        ps,
        re.IGNORECASE
    )

    if m:
        return f"service|{m.group(1).lower()}"

    #
    # SERVICE REGISTRY START TYPE
    #

    m = re.search(
        r"services\\([^\\']+)",
        ps,
        re.IGNORECASE
    )

    if m:

        service_name = m.group(1).lower()

        if service_name not in (
            "lanmanserver",
            "lanmanworkstation",
            "netlogon",
        ):
            return f"service|{service_name}"

    #
    # ASR RULES
    #

    m = re.search(
        r"\\asr\\rules.*?'([0-9a-f\-]{36})'",
        ps,
        re.IGNORECASE
    )

    if m:

        return normalize_registry_key(
            "registry|"
            "hklm:\\software\\policies\\microsoft\\windows defender\\windows defender exploit guard\\asr\\rules"
            f"|{m.group(1).lower()}"
        )

    #
    # $path + $name
    #

    path_match = re.search(
        r"\$path\s*=\s*'([^']+)'",
        ps,
        re.IGNORECASE
    )

    name_match = re.search(
        r"\$name\s*=\s*'([^']+)'",
        ps,
        re.IGNORECASE
    )

    if path_match and name_match:

        return normalize_registry_key(
            f"registry|"
            f"{path_match.group(1).lower()}|"
            f"{name_match.group(1).lower()}"
        )

    #
    # GET-ITEMPROPERTY
    #

    m = re.search(
        r"get-itemproperty\s*"
        r".*?-path\s+'([^']+)'"
        r".*?\)\.([a-zA-Z0-9_\-]+)",
        ps,
        re.IGNORECASE | re.DOTALL
    )

    if m:

        return normalize_registry_key(
            f"registry|"
            f"{m.group(1).lower()}|"
            f"{m.group(2).lower()}"
        )

    #
    # HKCU Direct Access
    #

    m = re.search(
        r"get-itemproperty\s*'([^']+)'\)\.([a-zA-Z0-9_\-]+)",
        ps,
        re.IGNORECASE
    )

    if m:

        return normalize_registry_key(
            f"registry|"
            f"{m.group(1).lower()}|"
            f"{m.group(2).lower()}"
        )

    #
    # HKEY_USERS SID Enumeration
    #

    path_match = re.search(
        r"join-path\s+\$_\.pspath\s+'([^']+)'",
        ps,
        re.IGNORECASE
    )

    name_match = re.search(
        r"-name\s+'([^']+)'",
        ps,
        re.IGNORECASE
    )

    if path_match and name_match:

        return normalize_registry_key(
            f"registry|"
            f"{path_match.group(1).lower()}|"
            f"{name_match.group(1).lower()}"
        )

    #
    # PRE-NORMALIZED REGISTRY
    #

    if lower_ps.startswith("registry|"):

        normalized = lower_ps

        normalized = re.sub(
            r"registry::hkey_users\\s-1-5-[^\\]+\*?\\",
            r"hkcu:\\",
            normalized,
            flags=re.IGNORECASE
        )

        normalized = re.sub(
            r"registry::hkey_users\\s-1-5-21\*",
            r"hkcu:",
            normalized,
            flags=re.IGNORECASE
        )

        normalized = normalized.replace(
            "registry::hkey_users\\",
            "hkcu:\\"
        )

        normalized = normalized.replace(
            "\\netlogon\\parameter|",
            "\\netlogon\\parameters|"
        )

        normalized = normalized.replace(
            "\\parameters\\|",
            "\\parameters|"
        )

        normalized = normalized.replace(
            "\\|",
            "|"
        )

        normalized = re.sub(
            r"\\\\+",
            r"\\",
            normalized
        )

        return normalized

    #
    # PASS THROUGH
    #

    for prefix in (

        "registry|",
        "privilege|",
        "account|",
        "feature|",
        "service|",
        "auditpol.exe",
        "net accounts",

    ):

        if lower_ps.startswith(prefix):
            return lower_ps

    return lower_ps

# ============================================================
# KEY BUILDING
# ============================================================

def build_key(block_text):

    description = normalize_description(
        get_field(
            block_text,
            "description"
        )
    )

    reference = normalize_reference(
        get_field(
            block_text,
            "reference"
        )
    )

    #
    # Eliminate bad SEE_ALSO values
    #
    if reference.upper().startswith(
        "SEE_ALSO"
    ):
        reference = ""

    value_type = get_field(
        block_text,
        "value_type"
    ).strip()

    value_data = normalize_value_data(
        get_field(
            block_text,
            "value_data"
        )
    )

    check_type = get_field(
        block_text,
        "check_type"
    ).strip()

    item_type = get_field(
        block_text,
        "type"
    ).strip()

    powershell_args = normalize_powershell(
        get_field(
            block_text,
            "powershell_args"
        )
    )


    right_type = get_field(
        block_text,
        "right_type"
    ).strip().lower()

    if right_type:

        powershell_args = (
            f"privilege|{right_type}"
        )


    #
    # Human-readable normalized key
    #
    normalized_key = "|".join([

        item_type,

        description,

        reference,

        value_type,

        value_data,

        check_type,

        powershell_args

    ])

    return {

        "type":
            item_type,

        "description":
            description,

        "reference":
            reference,

        "value_type":
            value_type,

        "value_data":
            value_data,

        "check_type":
            check_type,

        "powershell_args":
            powershell_args,

        "normalized_key":
            normalized_key

    }

def description_match(desc1, desc2):

    ratio = difflib.SequenceMatcher(
        None,
        desc1.lower(),
        desc2.lower()
    ).ratio()

    return ratio >= 0.60

def similarity(value1, value2):

    value1 = str(value1).strip().lower()
    value2 = str(value2).strip().lower()

    #
    # Registry identities
    #

    if (
        value1.startswith("registry|")
        and value2.startswith("registry|")
    ):
        return 100 if value1 == value2 else 0

    #
    # User rights identities
    #

    if (
        value1.startswith("privilege|")
        and value2.startswith("privilege|")
    ):
        return 100 if value1 == value2 else 0

    #
    # Feature identities
    #

    if (
        value1.startswith("feature|")
        and value2.startswith("feature|")
    ):
        return 100 if value1 == value2 else 0

    #
    # Auditpol
    #

    if (
        value1.startswith("auditpol.exe")
        and value2.startswith("auditpol.exe")
    ):
        return 100 if value1 == value2 else 0

    #
    # Net Accounts
    #

    if (
        value1.startswith("net accounts")
        and value2.startswith("net accounts")
    ):
        return 100 if value1 == value2 else 0

    #
    # Account identities
    #

    if (
        value1.startswith("account|")
        and value2.startswith("account|")
    ):
        return 100 if value1 == value2 else 0


    if not value1 and not value2:
        return 100

    return round(
        difflib.SequenceMatcher(
            None,
            value1,
            value2
        ).ratio() * 100,
        1
    )


def normalize_powershell_semantics(ps):

    ps = (ps or "").lower()

    # If already in pre-normalized 'registry|' form, normalize and return early
    if ps.startswith("registry|"):

        normalized = ps

        normalized = re.sub(
            r"registry::hkey_users\\s-1-5-[^\\]+\*?\\",
            r"hkcu:\\",
            normalized,
            flags=re.IGNORECASE
        )

        normalized = re.sub(
            r"registry::hkey_users\\s-1-5-21\*",
            r"hkcu:",
            normalized,
            flags=re.IGNORECASE
        )

        normalized = normalized.replace(
            "registry::hkey_users\\",
            "hkcu:\\"
        )

        normalized = normalized.replace(
            "\\netlogon\\parameter|",
            "\\netlogon\\parameters|"
        )

        normalized = normalized.replace(
            "\\parameters\\|",
            "\\parameters|"
        )

        normalized = normalized.replace(
            "\\|",
            "|"
        )

        normalized = re.sub(
            r"\\\\+",
            r"\\",
            normalized
        )

        return normalized

    #
    # ADCS aliases
    #
    if (
        "adcs" in ps
        or
        "certsvc" in ps
    ):
        return "feature|adcs"

    #
    # Printer driver installation policy
    #
    if (
        "lanman print services\\servers" in ps
        and
        "addprinterdrivers" in ps
    ):
        return (
            "registry|print|servers|addprinterdrivers"
        )

    #
    # Common registry-value based controls
    #
    registry_values = [

        "enableforcedlogoff",
        "shutdownwithoutlogon",
        "restrictremotesam",
        "fallowtogethelp",
        "forcekerberosforrpc",
        "allowbuildpreview",
        "enableappinstaller",
        "enablehashoverride",
        "disableantispyware",
        "disableioavprotection",
        "dohpolicy",

    ]

    property_name = None

    # Canonicalize common synonyms for SMB signing properties so related
    # registry properties (Enable/RequireSecuritySignature) normalize the same.
    smb_sig_synonyms = [
        r"enablesecuritysignature",
        r"requiresecuritysignature",
        r"requiresecuritysigning",
        r"require_security_signature",
        r"require_security_signing",
        r"securitysignature",
        r"securitysigning",
    ]

    for syn in smb_sig_synonyms:
        if re.search(rf"\b{syn}\b", ps, re.IGNORECASE):
            property_name = "enablesecuritysignature"
            break

    for item in registry_values:
        if item in ps:
            property_name = item
            break

    if property_name:

        path_match = re.search(
            r"hk(?:lm|cu):\\[^'\";\)\s]+",
            ps,
            re.IGNORECASE
        )

        if path_match:

            registry_path = (
                path_match.group(0)
                .lower()
            )

            return (
                f"registry|"
                f"{registry_path}|"
                f"{property_name}"
            )

    return ps

def strip_duplicate_tag(text):

    return re.sub(
        r"^\[DUPLICATE.*?\]\s*",
        "",
        text
    )

def score_keys(base_key, target_key):

    desc_score = similarity(
        strip_duplicate_tag(
            base_key["description"]
        ),
        strip_duplicate_tag(
            target_key["description"]
        )
    )

    ref_score = similarity(
        base_key["reference"],
        target_key["reference"]
    )

    value_type_score = similarity(
        base_key["value_type"],
        target_key["value_type"]
    )

    ref_score = similarity(
        base_key["reference"],
        target_key["reference"]
    )

    value_type_score = similarity(
        base_key["value_type"],
        target_key["value_type"]
    )

    value_data_score = similarity(
        base_key["value_data"],
        target_key["value_data"]
    )

    check_type_score = similarity(
        base_key["check_type"],
        target_key["check_type"]
    )


    powershell_score = similarity(

        normalize_powershell_semantics(
            base_key["powershell_args"]
        ),

        normalize_powershell_semantics(
            target_key["powershell_args"]
        )
    )

    total_score = (

        desc_score *
        WEIGHTS["description"] / 100

        +

        ref_score *
        WEIGHTS["reference"] / 100

        +

        value_type_score *
        WEIGHTS["value_type"] / 100

        +

        value_data_score *
        WEIGHTS["value_data"] / 100

        +

        check_type_score *
        WEIGHTS["check_type"] / 100

        +

        powershell_score *
        WEIGHTS["powershell_args"] / 100
    )

    return {

        "overall_score":
            round(total_score, 1),

        "description_score":
            desc_score,

        "reference_score":
            ref_score,

        "value_type_score":
            value_type_score,

        "value_data_score":
            value_data_score,

        "check_type_score":
            check_type_score,

        "powershell_score":
            powershell_score,
    }


def keys_match(base_key, target_key):

    if not hasattr(keys_match, "_shown"):
        keys_match._shown = True

    scores = score_keys(
        base_key,
        target_key
    )

    # Debug: print detailed info for signature-related controls
    try:
        if (
            "enablesecuritysignature" in (base_key.get("powershell_args") or "").lower()
            or
            "enablesecuritysignature" in (target_key.get("powershell_args") or "").lower()
        ):
            dbg_print("\nDEBUG SIGNATURE CHECK")
            dbg_print("BASE raw PS:", repr(base_key.get("powershell_args")))
            dbg_print("TARGET raw PS:", repr(target_key.get("powershell_args")))
            dbg_print("BASE normalized semantics:", repr(normalize_powershell_semantics(base_key.get("powershell_args"))))
            dbg_print("TARGET normalized semantics:", repr(normalize_powershell_semantics(target_key.get("powershell_args"))))
            dbg_print("SCORES:", scores)
    except Exception:
        pass

    base_value = (
        base_key["value_data"]
        .strip()
        .lower()
    )

    target_value = (
        target_key["value_data"]
        .strip()
        .lower()
    )

    base_ps = (
        base_key["powershell_args"]
        .strip()
        .lower()
    )

    target_ps = (
        target_key["powershell_args"]
        .strip()
        .lower()
    )

    base_desc = (
        base_key["description"]
        .lower()
        .strip()
    )

    target_desc = (
        target_key["description"]
        .lower()
        .strip()
    )

    # Force-match RestrictRemoteSAM when semantics include the property
    # and the expected values are identical. This catches variations in
    # how the property is accessed while ensuring value parity.
    try:
        base_norm = normalize_powershell_semantics(
            base_key.get("powershell_args", "")
        )

        target_norm = normalize_powershell_semantics(
            target_key.get("powershell_args", "")
        )

        if ("restrictremotesam" in base_norm) or ("restrictremotesam" in target_norm):
            if base_value == target_value:
                return True
    except Exception:
        pass

    #
    # MS Only / DC Only segregation
    #

    desc_base = base_desc.replace(".", " ")
    desc_target = target_desc.replace(".", " ")

    base_is_ms = "ms only" in desc_base
    target_is_ms = "ms only" in desc_target

    base_is_dc = "dc only" in desc_base
    target_is_dc = "dc only" in desc_target

    if base_is_ms != target_is_ms:
        return False

    #
    # Don't allow DC-only controls
    # to match non-DC controls
    #

    if base_is_dc != target_is_dc:
        return False

    #
    # WMI
    #

    if (
        base_key["type"] == "WMI_POLICY"
        and target_key["type"] == "WMI_POLICY"
    ):
        return (
            base_key["normalized_key"]
            ==
            target_key["normalized_key"]
        )

    if (
        base_key["type"] == "WMI_POLICY"
        or target_key["type"] == "WMI_POLICY"
    ):
        return False

    if (
        base_key["type"] == "ANONYMOUS_SID_SETTING"
        and
        target_key["type"] == "AUDIT_POWERSHELL"
        and
        "turnoffanonymousblock" in target_ps
    ):
        return True

    if (
        target_key["type"] == "ANONYMOUS_SID_SETTING"
        and
        base_key["type"] == "AUDIT_POWERSHELL"
        and
        "turnoffanonymousblock" in base_ps
    ):
        return True

   #
    # Exact normalized key
    #

    if (
        base_key.get("normalized_key")
        and
        target_key.get("normalized_key")
        and
        base_key["normalized_key"]
        ==
        target_key["normalized_key"]
    ):
        return True

    #
    # PASSWORD POLICY CROSSWALKS
    #

    PASSWORD_POLICY_MAPPINGS = {

        "complexity password requirements": [
            "passwordcomplexity",
            "complexity",
        ],

        "encryption password reversible": [
            "cleartextpassword",
            "reversible",
        ],

        "admins lockout password": [
            "allowadministratoraccountlockout",
            "lockout",
        ],

        "expire force hours logoff logon network security when": [
            "force user logoff",
            "enableforcedlogoff",
        ],

        "relax minimum password length": [
            "relaxminimumpasswordlengthlimits",
            "minimum password length",
        ],

        "account lockout duration": [
            "lockout duration",
        ],

        "account lockout threshold": [
            "lockout threshold",
        ],

        "reset account lockout counter after": [
            "lockout observation",
            "lockout observation window",
        ],

        "allow administrator account lockout": [
            "lockout threshold",
        ],
    }

    #
    # PASSWORD_POLICY -> AUDIT_POWERSHELL
    #

    if (
        base_key["type"] == "PASSWORD_POLICY"
        and
        target_key["type"] == "AUDIT_POWERSHELL"
    ):

        policy = (
            base_key.get(
                "description",
                ""
            ).lower()
        )
    
    if (
        "account lockout duration" in base_desc
        or
        "account lockout duration" in target_desc
    ):
        dbg_print("BASE :", repr(base_desc))
        dbg_print("TARGET:", repr(target_desc))


    #
    # AUDIT_POWERSHELL -> PASSWORD_POLICY
    #

    if (
        target_key["type"] == "PASSWORD_POLICY"
        and
        base_key["type"] == "AUDIT_POWERSHELL"
    ):

        policy = (
            target_key.get(
                "description",
                ""
            ).lower()
        )

    #
    # Password Complexity
    #

    if (
        "password" in base_desc
        and "complexity" in base_desc
        and "password" in target_desc
        and "complexity" in target_desc
        and scores["reference_score"] >= 90
    ):
        return True

    #
    # Relax Minimum Password Length
    #

    if (
        "relaxminimumpasswordlengthlimits"
        in base_ps
        and
        "minimum password length"
        in target_ps
    ):
        return True

    if (
        "relaxminimumpasswordlengthlimits"
        in target_ps
        and
        "minimum password length"
        in base_ps
    ):
        return True

    #
    # Allow Administrator Account Lockout
    #

    if (
        base_key["type"] == "AUDIT_POWERSHELL"
        and
        target_key["type"] == "PASSWORD_POLICY"
    ):
        if (
            "allowadministratoraccountlockout"
            in base_ps
            and
            "admin" in target_desc
            and
            "lockout" in target_desc
        ):
            return True

    if (
        target_key["type"] == "AUDIT_POWERSHELL"
        and
        base_key["type"] == "PASSWORD_POLICY"
    ):
        if (
            "allowadministratoraccountlockout"
            in target_ps
            and
            "admin" in base_desc
            and
            "lockout" in base_desc
        ):
            return True


    #
    # PASSWORD_POLICY
    #

    if (
        base_key["type"] == "PASSWORD_POLICY"
        and target_key["type"] == "PASSWORD_POLICY"
    ):

        if (
            scores["description_score"] >= 80
        ):
            return True

        return (

            scores["description_score"] >= 70

            and

            (
                not base_key["reference"]
                or
                not target_key["reference"]
                or
                scores["reference_score"] >= 90
            )

        )
    #
    # CHECK_ACCOUNT -> AUDIT_POWERSHELL
    #

    if (
        base_key["type"] == "CHECK_ACCOUNT"
        and
        target_key["type"] == "AUDIT_POWERSHELL"
    ):


        if (
            "guest rename" in base_desc
            and
            "guest rename" in target_desc
        ):
            return True

        if (
            "admin" in base_desc
            and
            "administrator" in target_desc
            and
            "rename" in target_desc
        ):
            return True

    if (
        target_key["type"] == "CHECK_ACCOUNT"
        and
        base_key["type"] == "AUDIT_POWERSHELL"
    ):

        if (
            "admin" in target_desc
            and
            "administrator" in base_desc
            and
            "rename" in base_desc
        ):
            return True
    
    #
    # Administrator Rename
    #

    if (
        base_key["type"] == "CHECK_ACCOUNT"
        and
        target_key["type"] == "AUDIT_POWERSHELL"
    ):

        if (
            "admin local rename" in base_desc
            and
            "administrator rename" in target_desc
        ):
            return True

    if (
        target_key["type"] == "CHECK_ACCOUNT"
        and
        base_key["type"] == "AUDIT_POWERSHELL"
    ):

        if (
            "admin local rename" in target_desc
            and
            "administrator rename" in base_desc
        ):
            return True

    #
    # USER_RIGHTS_POLICY <-> AUDIT_POWERSHELL
    #

    if (
        {
            base_key["type"],
            target_key["type"]
        }
        ==
        {
            "USER_RIGHTS_POLICY",
            "AUDIT_POWERSHELL"
        }
    ):

            if (
                base_ps
                and
                target_ps
                and
                base_ps == target_ps
            ):
                return True

    #
    # USER_RIGHTS_POLICY
    #

    if (
        base_key["type"] == "USER_RIGHTS_POLICY"
        and
        target_key["type"] == "USER_RIGHTS_POLICY"
    ):

        if (
            base_ps ==
            "privilege|sedenynetworklogonright"
        ):
            dbg_print("BASE VALUE:", repr(base_key["value_data"]))
            dbg_print("TARGET VALUE:", repr(target_key["value_data"]))
            dbg_print("BASE CHECK:", repr(base_key["check_type"]))
            dbg_print("TARGET CHECK:", repr(target_key["check_type"]))

        if (
            base_ps ==
            "privilege|sedenyremoteinteractivelogonright"
        ):
            dbg_print("BASE VALUE:", repr(base_key["value_data"]))
            dbg_print("TARGET VALUE:", repr(target_key["value_data"]))
            dbg_print("BASE CHECK:", repr(base_key["check_type"]))
            dbg_print("TARGET CHECK:", repr(target_key["check_type"]))

        if (
            base_ps == target_ps
            and
            base_key["value_data"].strip().lower()
            ==
            target_key["value_data"].strip().lower()
        ):
            return True

        #
        # Exact privilege match
        #

        if base_ps == target_ps:

            #
            # Exact assignment match
            #

            if base_value == target_value:
                return True

            #
            # CHECK_SUPERSET handling
            #

            if (
                base_key.get("check_type", "")
                .upper()
                ==
                "CHECK_SUPERSET"
            ):

                base_parts = [

                    p.strip()

                    for p in re.split(
                        r"\|\||&&",
                        base_value
                    )

                    if p.strip()

                ]

                if all(
                    part in target_value
                    for part in base_parts
                ):
                    return True

            #
            # Same privilege and
            # nearly identical control
            #

            if (
                scores["description_score"] >= 90
                and
                scores["reference_score"] >= 90
            ):
                return True

    #
    # ANONYMOUS SID
    #

    if (
        base_key["type"] == "ANONYMOUS_SID_SETTING"
        and target_key["type"] == "ANONYMOUS_SID_SETTING"
    ):
        return True

    #
    # Account Lockout Policy Crosswalks
    #

    if (
        "net accounts" in base_ps
        and
        "net accounts" in target_ps
    ):

        #
        # Duration
        #
        def _extract_num(v):
            if not v:
                return None
            m = re.search(r"(\d+)", str(v))
            return int(m.group(1)) if m else None

        if (
            "lockout duration" in base_ps
            and
            "lockout duration" in target_ps
        ):
            bnum = _extract_num(base_key.get("value_data"))
            tnum = _extract_num(target_key.get("value_data"))
            if bnum is not None and tnum is not None:
                return bnum == tnum
            # fall back to strict equality when numeric parsing fails
            return base_key.get("value_data") == target_key.get("value_data")

        #
        # Threshold
        #
        if (
            "lockout threshold" in base_ps
            and
            "lockout threshold" in target_ps
        ):
            bnum = _extract_num(base_key.get("value_data"))
            tnum = _extract_num(target_key.get("value_data"))
            if bnum is not None and tnum is not None:
                return bnum == tnum
            return base_key.get("value_data") == target_key.get("value_data")

        #
        # Reset counter
        #
        if (
            (
                "lockout observation" in base_ps
                or
                "observation window" in base_ps
            )
            and
            (
                "lockout observation" in target_ps
                or
                "observation window" in target_ps
            )
        ):
            bnum = _extract_num(base_key.get("value_data"))
            tnum = _extract_num(target_key.get("value_data"))
            if bnum is not None and tnum is not None:
                return bnum == tnum
            return base_key.get("value_data") == target_key.get("value_data")

        if (
            "shutdownwithoutlogon" in base_ps
            or
            "shutdownwithoutlogon" in target_ps
        ):
            dbg_print("\nSHUTDOWN CHECK")
            dbg_print("BASE :", base_ps)
            dbg_print("TARGET:", target_ps)

        if (
            "enablesecuritysignature" in base_ps
            or
            "enablesecuritysignature" in target_ps
        ):
            dbg_print("\nSIGNATURE CHECK")
            dbg_print("BASE :", base_ps)
            dbg_print("TARGET:", target_ps)

        if (
            "restrictremotesam" in base_ps
            or
            "restrictremotesam" in target_ps
        ):
            dbg_print("\nREMOTE SAM CHECK")
            dbg_print("BASE :", base_ps)
            dbg_print("TARGET:", target_ps)

        if (
            base_ps
            ==
            "registry|hklm:\\software\\microsoft\\windows\\currentversion\\policies\\system|shutdownwithoutlogon"
            and
            target_ps
            ==
            "registry|hklm:\\software\\microsoft\\windows\\currentversion\\policies\\system|shutdownwithoutlogon"
        ):
            return True

        if (
            base_ps
            ==
            "registry|hklm:\\system\\currentcontrolset\\services\\lanmanworkstation\\parameters|enablesecuritysignature"
            and
            target_ps
            ==
            "registry|hklm:\\system\\currentcontrolset\\services\\lanmanworkstation\\parameters|enablesecuritysignature"
        ):
            return True

        # SMB-signing crosswalk: tolerate lanmanserver <-> lanmanworkstation
        # variations so Enable/RequireSecuritySignature synonyms normalize
        # to the same logical control even when the registry path differs
        # between client and server controls.
        try:
            base_norm = normalize_powershell_semantics(base_key.get("powershell_args", ""))
            target_norm = normalize_powershell_semantics(target_key.get("powershell_args", ""))

            if (
                ("enablesecuritysignature" in base_norm or "enablesecuritysignature" in target_norm)
                and (
                    "lanmanserver" in base_norm
                    or "lanmanworkstation" in base_norm
                    or "lanmanserver" in target_norm
                    or "lanmanworkstation" in target_norm
                )
            ):
                # If values are identical, accept immediately
                if base_key["value_data"].strip().lower() == target_key["value_data"].strip().lower():
                    return True

                # Otherwise accept when descriptions and references are near-identical
                if scores["description_score"] >= 85 and scores["reference_score"] >= 90:
                    return True
        except Exception:
            pass

        # Description-based SMB signing crosswalk: some controls reference
        # the SMB signing policy in the description but have unrelated
        # powershell checks; allow matching when descriptions/references
        # strongly align and the value_data is the same.
        try:
            if (
                (
                    "digitally sign" in base_desc
                    or "digitally sign" in target_desc
                    or "sign communications" in base_desc
                    or "sign communications" in target_desc
                )
                and base_key["value_data"].strip().lower() == target_key["value_data"].strip().lower()
                and scores["description_score"] >= 75
                and scores["reference_score"] >= 85
            ):
                return True
        except Exception:
            pass

        if (
            base_ps
            ==
            "registry|hklm:\\system\\currentcontrolset\\control\\lsa|restrictremotesam"
            and
            target_ps
            ==
            "registry|hklm:\\system\\currentcontrolset\\control\\lsa|restrictremotesam"
        ):
            return True

        # RestrictRemoteSAM crosswalk: tolerate variations in how the
        # property is retrieved (Get-ItemProperty, property access, etc.)
        try:
            base_norm = normalize_powershell_semantics(base_key.get("powershell_args", ""))
            target_norm = normalize_powershell_semantics(target_key.get("powershell_args", ""))

            if ("restrictremotesam" in base_norm) or ("restrictremotesam" in target_norm):
                # Prefer exact value match
                if base_key["value_data"].strip().lower() == target_key["value_data"].strip().lower():
                    return True

                # Allow when descriptions and references strongly align
                if scores["description_score"] >= 85 and scores["reference_score"] >= 90:
                    return True
        except Exception:
            pass

    #
    # Identity controls
    #

    for prefix in (

        "registry|",
        "privilege|",
        "account|",
        "feature|",
        "service|",
        "auditpol.exe",
        "net accounts",

    ):


        if (
            base_ps.startswith(prefix)
            and
            target_ps.startswith(prefix)
            and
            base_ps == target_ps
        ):

            # print(
            #     "IDENTITY MATCH:",
            #     base_key["type"],
            #     "->",
            #     target_key["type"],
            #     "|",
            #     base_ps
            # )

            return True

    #
    # Server checks
    #

    if (
        base_desc.startswith("check if server")
        and
        target_desc.startswith("check if server")
    ):

        return (
            base_key["value_data"]
            ==
            target_key["value_data"]
        )

    #
    # Description
    #

    if (
        scores["description_score"]
        <
        MIN_THRESHOLDS["description"]
    ):
        return False

    #
    # Reference
    #

    base_ref = (
        base_key["reference"]
        .strip()
    )

    target_ref = (
        target_key["reference"]
        .strip()
    )

    if base_ref and target_ref:

        if (
            scores["reference_score"]
            <
            MIN_THRESHOLDS["reference"]
        ):
            return False

    #
    # Value Type
    #

    if (
        scores["value_type_score"]
        <
        MIN_THRESHOLDS["value_type"]
    ):
        return False

    #
    # Skip value comparison for
    # identity controls
    #

    skip_value_check = False

    for prefix in (

        "registry|",
        "privilege|",
        "account|",
        "feature|",
        "service|",
        "auditpol.exe",
        "net accounts",

    ):

        if (
            base_ps.startswith(prefix)
            and
            target_ps.startswith(prefix)
            and
            base_ps == target_ps
        ):

            skip_value_check = True
            break

    if (
        not skip_value_check
        and
        scores["value_data_score"]
        <
        MIN_THRESHOLDS["value_data"]
    ):
        return False


    #
    # Check Type
    #

    if (
        scores["check_type_score"]
        <
        MIN_THRESHOLDS["check_type"]
    ):
        return False

    #
    # PowerShell
    #

    if base_ps and target_ps:

        if (
            scores["powershell_score"]
            <
            MIN_THRESHOLDS["powershell_args"]
        ):
            return False

    #
    # LAST CHANCE MATCHING
    #

    if (

        base_key["type"]
        ==
        target_key["type"]

        and

        base_key["type"] in (
            "CHECK_ACCOUNT",
            "USER_RIGHTS_POLICY",
            "PASSWORD_POLICY",
        )

    ):

        if (
            base_ps
            and
            target_ps
            and
            base_ps == target_ps
        ):
            return True

        if (
            scores["description_score"] >= 85
        ):
            return True

    if (
        base_key["type"] in (
            "CHECK_ACCOUNT",
            "USER_RIGHTS_POLICY",
            "PASSWORD_POLICY",
        )
        or
        target_key["type"] in (
            "CHECK_ACCOUNT",
            "USER_RIGHTS_POLICY",
            "PASSWORD_POLICY",
        )
    ):

        print(
            "LAST CHANCE:",
            base_key["type"],
            "->",
            target_key["type"],
            "|",
            scores["description_score"],
            "|",
            base_desc,
            "|",
            target_desc
        )

    fallback_match = (
        scores["overall_score"]
        >= MATCH_THRESHOLD
    )

    if (
        "shutdownwithoutlogon" in base_ps
        or
        "shutdownwithoutlogon" in target_ps
    ):
        dbg_print("\nSHUTDOWN")
        dbg_print("BASE  :", base_ps)
        dbg_print("TARGET:", target_ps)

    if (
        "enablesecuritysignature" in base_ps
        or
        "enablesecuritysignature" in target_ps
    ):
        dbg_print("\nSIGNATURE")
        dbg_print("BASE  :", base_ps)
        dbg_print("TARGET:", target_ps)

    if (
        "restrictremotesam" in base_ps
        or
        "restrictremotesam" in target_ps
    ):
        dbg_print("\nREMOTE SAM")
        dbg_print("BASE  :", base_ps)
        dbg_print("TARGET:", target_ps)


    return fallback_match

# ============================================================
# BLOCK HANDLING
# ============================================================

def block_is_commented(lines):

    for line in lines:

        stripped = line.lstrip()

        if (
            "<custom_item>" in stripped
            or "#<custom_item>" in stripped
        ):
            return stripped.startswith("#")

    return False


def comment_block(lines):

    result = []

    for line in lines:

        if line.lstrip().startswith("#"):
            result.append(line)
        else:
            result.append("#" + line)

    return result




# ============================================================
# PROCESSING
# ============================================================

def process_files(base_path, target_path):

    print(f"\nBase file   : {base_path}")
    print(f"Target file : {target_path}")

    backup_path = target_path.with_suffix(
        target_path.suffix + ".bak"
    )

    output_path = target_path.with_name(
        f"{target_path.stem}_commented_{DATE_STR}"
        f"{target_path.suffix}"
    )

    matches_xlsx = target_path.with_name(
        f"{target_path.stem}_matches_{DATE_STR}.xlsx"
    )

    unmatched_xlsx = target_path.with_name(
        f"{target_path.stem}_unmatched_{DATE_STR}.xlsx"
    )

    high_confidence_xlsx = target_path.with_name(
        f"{target_path.stem}_high_confidence_unmatched_{DATE_STR}.xlsx"
    )
    
    policy_difference_xlsx = target_path.with_name(
        f"{target_path.stem}_policy_differences_{DATE_STR}.xlsx"
    )
    
    base_unmatched_xlsx = target_path.with_name(
        f"{target_path.stem}_base_unmatched_{DATE_STR}.xlsx"
    )


    shutil.copy2(target_path, backup_path)

    print(f"Backup created: {backup_path}")

    base_lines = base_path.read_text(
        encoding="utf-8",
        errors="ignore"
    ).splitlines(keepends=True)

    target_lines = target_path.read_text(
        encoding="utf-8",
        errors="ignore"
    ).splitlines(keepends=True)
    
    base_blocks = []
    target_blocks = []

    for block in parse_blocks(base_lines, block_types=("custom_item",)):
        block_text = "".join(block["lines"])
        base_blocks.append({
            "start": block["start"],
            "end": block["end"],
            "lines": block["lines"],
            "key": build_key(block_text),
            "commented": block["lines"][0].lstrip().startswith("#"),
        })

    for block in parse_blocks(target_lines, block_types=("custom_item",)):
        block_text = "".join(block["lines"])
        target_blocks.append({
            "start": block["start"],
            "end": block["end"],
            "lines": block["lines"],
            "key": build_key(block_text),
            "commented": block["lines"][0].lstrip().startswith("#"),
        })

    from collections import defaultdict

    duplicate_groups = defaultdict(list)

    for block in base_blocks:

        # Group duplicates by normalized_key so identical registry/ps
        # identities are treated as duplicates even when descriptions vary.
        nk = block["key"].get("normalized_key", "").strip().lower()

        duplicate_groups[nk].append(block)

    for group in duplicate_groups.values():

        if len(group) > 1:

            total = len(group)

            for idx, block in enumerate(group, start=1):

                block["duplicate_label"] = (
                    f"DUPLICATE {idx} OF {total}"
                )

                block["display_description"] = (
                    f"[DUPLICATE {idx}/{total}] "
                    f"{block['key']['description']}"
                )
                # Mark all except the first as duplicates for matching
                # Keep the first occurrence as the representative
                if idx == 1:
                    block["is_duplicate"] = False
                else:
                    block["is_duplicate"] = True

    for block in base_blocks:

        block.setdefault(
            "display_description",
            block["key"]["description"]
        )

    # Remove duplicate blocks from the active base set used for matching
    # after tagging them with duplicate labels. This ensures duplicates
    # are not counted or listed in unmatched reports.
    base_blocks = [
        b for b in base_blocks
        if not b.get("is_duplicate", False)
    ]


    from collections import Counter

    base_privs = Counter()

    for block in base_blocks:

        ps = (
            block["key"]
            .get("powershell_args", "")
            .lower()
        )

        if ps.startswith("privilege|"):
            base_privs[ps] += 1


    # for privilege, count in sorted(base_privs.items()):

    #     if count > 1:
    #         print(count, privilege)

    target_privs = Counter()

    for block in target_blocks:

        ps = (
            block["key"]
            .get("powershell_args", "")
            .lower()
        )

        if ps.startswith("privilege|"):
            target_privs[ps] += 1

    

    # for privilege, count in sorted(target_privs.items()):

    #     if count > 1:
    #         print(count, privilege)

    output_lines = target_lines[:]

    match_rows = []
    unmatched_rows = []
    high_confidence_unmatched = []
    value_changed_matches = []

    matched_base_indexes = set()
    matched_target_indexes = set()

    base_unmatched_rows = []
    matched_shared_privileges = set()


    matched = 0
    commented = 0

    with Progress(
        SpinnerColumn(style="green"),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=50),
        MofNCompleteColumn(),
        TextColumn("[green]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
    ) as progress:

        task = progress.add_task(
            "Matching Controls",
            total=len(target_blocks)
        )

        for target in reversed(target_blocks):

            progress.update(
                task,
                description=f"Matching Controls (Matched={matched})",
                advance=1
            )

            target_key = target["key"]

            matched_state = None
            matched_base_key = None

            best_score = 0
            best_base_desc = ""
            best_base_ps = ""

            for base in base_blocks:

                #
                # Don't allow one base control
                # to match multiple targets
                #
                if id(base) in matched_base_indexes:
                    continue

                scores = score_keys(
                    base["key"],
                    target_key
                )

                if scores["overall_score"] > best_score:

                    best_score = scores["overall_score"]

                    best_base_desc = (
                        base["key"]["description"]
                    )

                    best_base_ps = (
                        base["key"]["powershell_args"]
                    )

                if keys_match(
                    base["key"],
                    target_key
                ):
                    # print(
                    #     "\nMATCH FOUND:",
                    #     base["key"]["description"],
                    #     "->",
                    #     target_key["description"]
                    # )

                    matched_state = base["commented"]

                    # if (
                    #     "enablesecuritysignature"
                    #     in base["key"]["powershell_args"].lower()
                    # ):
                    #     print(
                    #         "\nMATCHED ENABLESECURITYSIGNATURE"
                    #     )

                    #     print(
                    #         "BASE:",
                    #         base.get(
                    #             "display_description",
                    #             base["key"]["description"]
                    #         )
                    #     )

                    #     print(
                    #         "TARGET:",
                    #         target_key["description"]
                    #     )

                    #     print(
                    #         "SCORE:",
                    #         scores["overall_score"]
                    #     )

                    if ps in KNOWN_SHARED_PRIVILEGES:

                        matched_shared_privileges.add(ps)
                    #
                    # Track controls whose expected values changed
                    #

                    if (
                        base["key"]["value_data"]
                        !=
                        target_key["value_data"]
                    ):

                        value_changed_matches.append({

                            "Description":
                                base.get(
                                    "display_description",
                                    base["key"]["description"]
                                ),

                            "Base Value":
                                base["key"]["value_data"],

                            "Target Value":
                                target_key["value_data"],

                            "Base PowerShell":
                                base["key"]["powershell_args"],

                            "Target PowerShell":
                                target_key["powershell_args"]

                        })

                    match_rows.append({

                        "Overall Score":
                            scores["overall_score"],

                        "Description %":
                            scores["description_score"],

                        "Reference %":
                            scores["reference_score"],

                        "Value Type %":
                            scores["value_type_score"],

                        "Value Data %":
                            scores["value_data_score"],

                        "Check Type %":
                            scores["check_type_score"],

                        "PowerShell %":
                            scores["powershell_score"],

                        "Target Description":
                            target_key["description"],
                                                
                        "Base Description":
                            base.get(
                                "display_description",
                                base["key"]["description"]
                            ),

                        "Target Reference":
                            target_key["reference"],

                        "Base Reference":
                            base["key"]["reference"],

                        "Target Value Data":
                            target_key["value_data"],

                        "Base Value Data":
                            base["key"]["value_data"],

                        "Target Powershell":
                            target_key["powershell_args"],

                        "Base Powershell":
                            base["key"]["powershell_args"],

                        "Base Commented":
                            matched_state,

                        "Target Key":
                            target_key["normalized_key"],

                        "Base Key":
                            base["key"]["normalized_key"],
                                                    
                        "Policy Difference":
                            (
                                "YES"
                                if base["key"]["value_data"]
                                != target_key["value_data"]
                                else "NO"
                            ),

                        "Base Expected Value":
                            base["key"]["value_data"],

                        "Target Expected Value":
                            target_key["value_data"],
                        


                    })

                    matched += 1

                    matched_base_indexes.add(
                        id(base)
                    )

                    # Allow a target to match multiple base controls when
                    # the normalized_key and expected values are identical.
                    try:
                        base_nk = base["key"]["normalized_key"]
                        target_nk = target_key["normalized_key"]
                        base_val = base["key"]["value_data"].strip().lower()
                        target_val = target_key["value_data"].strip().lower()

                        if not (
                            base_nk == target_nk
                            and base_val == target_val
                        ):
                            matched_target_indexes.add(
                                target_key["normalized_key"]
                            )
                    except Exception:
                        matched_target_indexes.add(
                            target_key["normalized_key"]
                        )

                    ps = (
                        base["key"]["powershell_args"]
                        .strip()
                        .lower()
                    )

                    if ps in KNOWN_SHARED_PRIVILEGES:

                        matched_shared_privileges.add(ps)

                    break

            #
            # UNMATCHED
            #

            if (
                matched_state is None
                and
                target_key["normalized_key"]
                not in matched_target_indexes
            ):

                unmatched_rows.append({

                    "Description":
                        target_key["description"],

                    "Reference":
                        target_key["reference"],

                    "Value Type":
                        target_key["value_type"],

                    "Value Data":
                        target_key["value_data"],

                    "Check Type":
                        target_key["check_type"],

                    "PowerShell":
                        target_key["powershell_args"],

                    "Normalized Key":
                        target_key["normalized_key"],

                    "Best Score":
                        best_score,

                    "Closest Base Description":
                        best_base_desc,

                    "Closest Base PowerShell":
                        best_base_ps

                })

                #
                # HIGH CONFIDENCE UNMATCHED
                #

                if best_score >= 95:

                    high_confidence_unmatched.append({

                        "Description":
                            target_key["description"],

                        "Reference":
                            target_key["reference"],

                        "Value Type":
                            target_key["value_type"],

                        "Value Data":
                            target_key["value_data"],

                        "Check Type":
                            target_key["check_type"],

                        "PowerShell":
                            target_key["powershell_args"],

                        "Normalized Key":
                            target_key["normalized_key"],

                        "Best Score":
                            best_score,

                        "Closest Base Description":
                            best_base_desc,

                        "Closest Base PowerShell":
                            best_base_ps

                    })

                continue

            #
            # COMMENT TARGET BLOCK IF
            # COMMENTED IN BASE
            #

            if matched_state:

                output_lines[
                    target["start"]:
                    target["end"] + 1
                ] = comment_block(
                    target["lines"]
                )

                commented += 1

    seen_base_normalized = set()

    for base in base_blocks:

        ps = (
            base["key"]["powershell_args"]
            .strip()
            .lower()
        )

    #
    # SECOND PASS MATCHING
    #

    for target in target_blocks:

        target_desc = (
            target["key"]["description"]
            .lower()
        )

        if (
            "certificate"
            not in target_desc
        ):
            continue

        already_matched = any(
            row["Target Key"]
            ==
            target["key"]["normalized_key"]
            for row in match_rows
        )

        if already_matched:
            continue

        for base in base_blocks:
            if id(base) in matched_base_indexes:
              
                if (
                    "clients disconnect expire hours"
                    in target_key["description"]
                ):
                    print(
                        "SKIPPING ALREADY MATCHED BASE:",
                        base["key"]["description"]
                    )

                continue


            base_desc = (
                base["key"]["description"]
                .lower()
            )

            if (
                "certificate"
                in base_desc
            ):

                base_ps = normalize_powershell_semantics(
                    base["key"]["powershell_args"]
                )

                target_ps = normalize_powershell_semantics(
                    target["key"]["powershell_args"]
                )

                if base_ps == target_ps:

                    # print(
                    #     "\nSECOND PASS MATCH:",
                    #     target["key"]["description"]
                    # )


                    matched_base_indexes.add(
                        id(base)
                    )

                    # For certificate second-pass matches allow reuse of
                    # targets with identical normalized_key+value.
                    try:
                        base_nk = base["key"]["normalized_key"]
                        target_nk = target["key"]["normalized_key"]
                        base_val = base["key"]["value_data"].strip().lower()
                        target_val = target["key"]["value_data"].strip().lower()

                        if not (
                            base_nk == target_nk
                            and base_val == target_val
                        ):
                            try:
                                base_nk = base["key"]["normalized_key"]
                                target_nk = target["key"]["normalized_key"]
                                base_val = base["key"]["value_data"].strip().lower()
                                target_val = target["key"]["value_data"].strip().lower()

                                if not (
                                    base_nk == target_nk
                                    and base_val == target_val
                                ):
                                    matched_target_indexes.add(
                                        target["key"]["normalized_key"]
                                    )
                            except Exception:
                                matched_target_indexes.add(
                                    target["key"]["normalized_key"]
                                )
                    except Exception:
                        matched_target_indexes.add(
                            target["key"]["normalized_key"]
                        )

                    match_rows.append({

                        "Overall Score":
                            scores["overall_score"],

                        "Description %":
                            scores["description_score"],

                        "Reference %":
                            scores["reference_score"],

                        "Value Type %":
                            scores["value_type_score"],

                        "Value Data %":
                            scores["value_data_score"],

                        "Check Type %":
                            scores["check_type_score"],

                        "PowerShell %":
                            scores["powershell_score"],

                        "Target Description":
                            target_key["description"],

                        "Description":
                            base.get(
                                "display_description",
                                base["key"]["description"]
                            ),

                        "Target Reference":
                            target_key["reference"],

                        "Base Reference":
                            base["key"]["reference"],

                        "Target Value Data":
                            target_key["value_data"],

                        "Base Value Data":
                            base["key"]["value_data"],

                        "Target Powershell":
                            target_key["powershell_args"],

                        "Base Powershell":
                            base["key"]["powershell_args"],

                        "Base Commented":
                            matched_state,

                        "Target Key":
                            target_key["normalized_key"],

                        "Base Key":
                            base["key"]["normalized_key"],
                                                    
                        "Policy Difference":
                            (
                                "YES"
                                if base["key"]["value_data"]
                                != target_key["value_data"]
                                else "NO"
                            ),

                        "Base Expected Value":
                            base["key"]["value_data"],

                        "Target Expected Value":
                            target_key["value_data"],
                        
                        "Matched By": "SECOND_PASS"

                    })

                    matched += 1

                    break

    from collections import Counter

    base_counter = Counter(
        b["key"]["normalized_key"]
        for b in base_blocks
    )

    # Final-pass: if nearly all lockout controls matched, force-match any
    # remaining lockout base controls even when the expected value differs.
    try:
        base_lockouts = [
            b for b in base_blocks
            if (
                "net accounts" in (b["key"].get("powershell_args", "") or "").lower()
                and
                ("lockout" in (b["key"].get("powershell_args", "") or "").lower() or "lockout" in b["key"].get("description", "").lower())
            )
        ]

        total_lockouts = len(base_lockouts)

        if total_lockouts > 0:

            matched_lockouts = sum(
                1 for b in base_lockouts if id(b) in matched_base_indexes
            )

            # If all other lockouts are matched, force-match remaining
            if matched_lockouts >= total_lockouts - 1:

                for base in base_lockouts:

                    if id(base) in matched_base_indexes:
                        continue

                    # Find best target lockout candidate
                    best_score = 0
                    best_target = None

                    for target in target_blocks:

                        tps = (target["key"].get("powershell_args", "") or "").lower()

                        if "net accounts" not in tps:
                            continue

                        scores = score_keys(base["key"], target["key"])

                        if scores["overall_score"] > best_score:
                            best_score = scores["overall_score"]
                            best_target = (target, scores)

                    if best_target:

                        target, scores = best_target

                        match_rows.append({
                            "Overall Score": scores["overall_score"],
                            "Description %": scores["description_score"],
                            "Reference %": scores["reference_score"],
                            "Value Type %": scores["value_type_score"],
                            "Value Data %": scores["value_data_score"],
                            "Check Type %": scores["check_type_score"],
                            "PowerShell %": scores["powershell_score"],
                            "Target Description": target["key"]["description"],
                            "Base Description": base.get("display_description", base["key"]["description"]),
                            "Target Reference": target["key"]["reference"],
                            "Base Reference": base["key"]["reference"],
                            "Target Value Data": target["key"]["value_data"],
                            "Base Value Data": base["key"]["value_data"],
                            "Target Powershell": target["key"]["powershell_args"],
                            "Base Powershell": base["key"]["powershell_args"],
                            "Base Commented": base["commented"],
                            "Target Key": target["key"]["normalized_key"],
                            "Base Key": base["key"]["normalized_key"],
                            "Policy Difference": ("YES" if base["key"]["value_data"] != target["key"]["value_data"] else "NO"),
                            "Base Expected Value": base["key"]["value_data"],
                            "Target Expected Value": target["key"]["value_data"],
                        })

                        matched += 1

                        matched_base_indexes.add(id(base))

                        try:
                            base_nk = base["key"]["normalized_key"]
                            target_nk = target["key"]["normalized_key"]
                            base_val = base["key"]["value_data"].strip().lower()
                            target_val = target["key"]["value_data"].strip().lower()

                            if not (base_nk == target_nk and base_val == target_val):
                                matched_target_indexes.add(target["key"]["normalized_key"])
                        except Exception:
                            matched_target_indexes.add(target["key"]["normalized_key"])

    except Exception:
        pass

    print("\nDUPLICATE BASE CONTROLS")

    for k, c in base_counter.items():

        if c > 1:

            print(c, k)


    matched_base_keys = {
        row["Base Key"]
        for row in match_rows
    }

    #
    # Base controls that never matched
    #

    shared_privilege_matches = 0

    for base in base_blocks:

        if id(base) in matched_base_indexes:
            continue

        if (
            base["key"]["normalized_key"]
            in matched_base_keys
        ):
            continue

        ps = (
            base["key"]["powershell_args"]
            .strip()
            .lower()
        )

        #
        # Shared privilege reconciliation
        #

        if ps in KNOWN_SHARED_PRIVILEGES:

            if ps in matched_shared_privileges:

                matched_base_indexes.add(
                    id(base)
                )

                shared_privilege_matches += 1

                continue

        best_score = 0
        best_target_desc = ""
        best_target_value = ""
        best_target_ps = ""

        for target in target_blocks:

            scores = score_keys(
                base["key"],
                target["key"]
            )

            if scores["overall_score"] > best_score:

                best_score = scores["overall_score"]

                best_target_desc = (
                    target["key"]["description"]
                )

                best_target_value = (
                    target["key"]["value_data"]
                )

                best_target_ps = (
                    target["key"]["powershell_args"]
                )

        nk = base["key"]["normalized_key"]

        if nk in seen_base_normalized:
            continue

        # Special-case: if base is a RestrictRemoteSAM control and not
        # previously matched, attempt a final authoritative match against
        # any target that exposes the same RestrictRemoteSAM property
        # and identical expected value_data. This ensures variations in
        # how the property is retrieved still count as matches.
        try:
            base_norm = normalize_powershell_semantics(
                base["key"].get("powershell_args", "")
            )

            if "restrictremotesam" in (base_norm or ""):

                for target in target_blocks:
                    target_norm = normalize_powershell_semantics(
                        target["key"].get("powershell_args", "")
                    )

                    if "restrictremotesam" in (target_norm or ""):

                        if base["key"]["value_data"].strip().lower() == target["key"]["value_data"].strip().lower():

                            # register the match
                            sc = score_keys(base["key"], target["key"])

                            match_rows.append({

                                "Overall Score":
                                    sc["overall_score"],

                                "Description %":
                                    sc["description_score"],

                                "Reference %":
                                    sc["reference_score"],

                                "Value Type %":
                                    sc["value_type_score"],

                                "Value Data %":
                                    sc["value_data_score"],

                                "Check Type %":
                                    sc["check_type_score"],

                                "PowerShell %":
                                    sc["powershell_score"],

                                "Target Description":
                                    target["key"]["description"],
                                                    
                                "Base Description":
                                    base.get(
                                        "display_description",
                                        base["key"]["description"]
                                    ),

                                "Target Reference":
                                    target["key"]["reference"],

                                "Base Reference":
                                    base["key"]["reference"],

                                "Target Value Data":
                                    target["key"]["value_data"],

                                "Base Value Data":
                                    base["key"]["value_data"],

                                "Target Powershell":
                                    target["key"]["powershell_args"],

                                "Base Powershell":
                                    base["key"]["powershell_args"],

                                "Base Commented":
                                    base["commented"],

                                "Target Key":
                                    target["key"]["normalized_key"],

                                "Base Key":
                                    base["key"]["normalized_key"],
                                                        
                                "Policy Difference":
                                    (
                                        "YES"
                                        if base["key"]["value_data"]
                                        != target["key"]["value_data"]
                                        else "NO"
                                    ),

                                "Base Expected Value":
                                    base["key"]["value_data"],

                                "Target Expected Value":
                                    target["key"]["value_data"],

                            })

                            matched += 1

                            matched_base_indexes.add(id(base))

                            matched_target_indexes.add(
                                target["key"]["normalized_key"]
                            )

                            # mark as seen and skip adding to base_unmatched
                            seen_base_normalized.add(nk)

                            break

                if nk in seen_base_normalized:
                    continue
        except Exception:
            pass
        seen_base_normalized.add(nk)

        base_unmatched_rows.append({

            "Description":
                base.get(
                    "display_description",
                    base["key"]["description"]
                ),

            "Normalized Key":
                base["key"]["normalized_key"],

            "Type":
                base["key"]["type"],

            "Reference":
                base["key"]["reference"],

            "Value Type":
                base["key"]["value_type"],

            "Value Data":
                base["key"]["value_data"],

            "Check Type":
                base["key"]["check_type"],

            "PowerShell":
                base["key"]["powershell_args"],

            "MS Only":
                (
                    "MS ONLY"
                    in
                    base["key"]["description"].upper()
                ),

            "DC Only":
                (
                    "DC ONLY"
                    in
                    base["key"]["description"].upper()
                ),

            "Closest Target":
                best_target_desc,

            "Closest Target Value":
                best_target_value,

            "Closest Target PowerShell":
                best_target_ps,

            "Best Match Score":
                best_score,

            "Commented":
                base["commented"]

        })

    #
    # Append unmatched base controls
    #

    unmatched_base_count = 0

    output_lines.append(
        "\n\n"
        "<!-- ==================================================== -->\n"
        "<!-- UNMATCHED CONTROLS FROM BASE AUDIT                  -->\n"
        "<!-- ==================================================== -->\n\n"
    )

    unmatched_added_keys = set()

    for base in base_blocks:

        if id(base) in matched_base_indexes:
            continue

        nk = base["key"]["normalized_key"]

        if nk in matched_base_keys:
            continue

        if nk in unmatched_added_keys:
            continue

        unmatched_added_keys.add(nk)

        unmatched_base_count += 1

        output_lines.extend(
            base["lines"]
        )

        if (
            base["lines"]
            and
            not base["lines"][-1].endswith("\n")
        ):
            output_lines.append("\n")

        output_lines.append("\n")

    output_path.write_text(
        "".join(output_lines),
        encoding="utf-8"
    )

    pd.DataFrame(match_rows).to_excel(
        matches_xlsx,
        index=False,
        engine="openpyxl"
    )

    pd.DataFrame(unmatched_rows).to_excel(
        unmatched_xlsx,
        index=False,
        engine="openpyxl"
    )

    pd.DataFrame(
        high_confidence_unmatched
    ).to_excel(
        high_confidence_xlsx,
        index=False,
        engine="openpyxl"
    )

    pd.DataFrame(
        value_changed_matches
    ).to_excel(
        policy_difference_xlsx,
        index=False,
        engine="openpyxl"
    )

    pd.DataFrame(
        base_unmatched_rows
    ).to_excel(
        base_unmatched_xlsx,
        index=False,
        engine="openpyxl"
    )

    print()

    print(
        "\nMATCH ROWS:",
        len(match_rows)
    )

    print("MATCH SUMMARY")

    print(
        f"  Base controls          : "
        f"{len(base_blocks)}"
    )

    print(
        f"  Target controls        : "
        f"{len(target_blocks)}"
    )

    print(
        f"  Matched controls       : "
        f"{matched}"
    )

    print(
        f"  Shared Priv Matches    : "
        f"{shared_privilege_matches}"
    )

    print(
        f"  Unmatched controls     : "
        f"{len(unmatched_rows)}"
    )

    print(
        f"  High-score unmatched   : "
        f"{len(high_confidence_unmatched)}"
    )

    print(
        f"  Policy differences     : "
        f"{len(value_changed_matches)}"
    )

    print(
        f"  Base unmatched         : "
        f"{len(base_unmatched_rows)}"
    )

    print(
        f"  Commented blocks       : "
        f"{commented}"
    )

    print(
        f"  Base controls appended : "
        f"{unmatched_base_count}"
    )

    unmatched_user_rights = [

        row

        for row in base_unmatched_rows

        if row["Type"] == "USER_RIGHTS_POLICY"

    ]

    if unmatched_user_rights:


        print("\nUNMATCHED USER RIGHTS")

        for row in unmatched_user_rights:

            print(
                f"  • {row['Description']}"
            )

            print(
                f"      {row['PowerShell']}"
            )

            print(
                f"      Value: {row['Value Data']}"
            )

            print(
                f"      Check Type: {row['Check Type']}"
            )

            print(
                f"      Reference: {row['Reference']}"
            )

            print(
                f"      Closest Match: "
                f"{row['Closest Target']}"
            )

            print(
                f"      Closest Value: "
                f"{row['Closest Target Value']}"
            )

            print(
                f"      Closest PS: "
                f"{row['Closest Target PowerShell']}"
            )

            print(
                f"      Match Score: "
                f"{row['Best Match Score']}"
            )

            print(
                f"      MS Only: {row['MS Only']}"
            )

            print(
                f"      DC Only: {row['DC Only']}"
            )

    print("\nREPORTS")

    print(
        f"  Matches             : "
        f"{matches_xlsx}"
    )

    print(
        f"  Unmatched           : "
        f"{unmatched_xlsx}"
    )

    print(
        f"  High Confidence     : "
        f"{high_confidence_xlsx}"
    )

    print(
        f"  Policy Differences  : "
        f"{policy_difference_xlsx}"
    )

    print(
        f"  Base Unmatched      : "
        f"{base_unmatched_xlsx}"
    )

    print(
        "Match Rows:",
        len(match_rows)
    )

    print("\nOUTPUT")

    print(
        f"  {output_path}"
    )

# ============================================================
# MAIN
# ============================================================

def main():

    base_path = pathlib.Path(
        r"C:\PySC\Sync\Prod_MSSRV.audit"
    )

    target_path = pathlib.Path(
        r"C:\PySC\Sync\Merged-MSSRV-powershell.audit"
    )

    if not base_path.exists():
        print(f"Base file not found: {base_path}")
        return

    if not target_path.exists():
        print(f"Target file not found: {target_path}")
        return

    process_files(
        base_path,
        target_path
    )

if __name__ == "__main__":
    main()