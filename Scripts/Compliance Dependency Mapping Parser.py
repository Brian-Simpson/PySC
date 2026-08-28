
import argparse
import json
import logging
import re
import shlex
import requests
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor
import pandas as pd

from pathlib import Path

CACHE_FILE = Path("nist_cache.json")

def load_cache():
    if CACHE_FILE.exists():
        return json.loads(CACHE_FILE.read_text())
    return {}

def save_cache(cache):
    CACHE_FILE.write_text(json.dumps(cache, indent=2))

# ✅ Load once
NIST_CACHE = load_cache()

# -------------------------
# Logging Setup
# -------------------------
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

# -------------------------
# Precompiled Regex
# ✅ FIXED (removed HTML escaping)
# -------------------------
CUSTOM_BLOCK_PATTERN = re.compile(r'<custom_item>([\s\S]*?)</custom_item>', re.IGNORECASE)
KEY_VALUE_PATTERN = re.compile(r'^\s*([A-Za-z0-9_-]+)\s*:\s*(.*)')
INDEX_PATTERN_1 = re.compile(r'\b\d+\.(\d+)\s+-\s+[A-Z]{4,6}\s+-\s+')
INDEX_PATTERN_2 = re.compile(r'\b(\d+)\s+-\s+[A-Z]{4,6}\s+-\s+')
SIMPLE_PREFIX_PATTERN = re.compile(r'^(\d+(?:\.\d+)*)')

# -------------------------
# Control Mapping Load
# -------------------------
try:
    with open("control_mapping.json", "r") as f:
        CONTROL_MAP = json.load(f)
except Exception:
    CONTROL_MAP = {}

KNOWN_KEYWORDS = {
    "minimumpasswordlength",
    "passwordcomplexity",
    "maximumpasswordage",
    "minimumpasswordage",
    "cleartextpassword",
    "lockoutduration",
    "lockoutbadcount",
    "resetlockoutcount",
    "autoadminlogon",
    "defaultpassword",
    "disablerealtimemonitoring",
    "enablevirtualizationbasedsecurity",
    "shellsmartscreenlevel",
    "enablesmartscreen",
    "enumerateadministrators",
    "nolocalpasswordresetquestions",
}

# -------------------------
# NIST API Cache
# -------------------------
NIST_CACHE = {}

# -------------------------
# NIST Inference
# -------------------------
def infer_nist_control(audit_key: str) -> str:
    k = audit_key.lower()

    if any(x in k for x in ["password", "credential"]):
        return "IA-5(1)"

    if "lockout" in k:
        return "AC-7"

    if "logon" in k or "logoff" in k:
        return "AU-3"

    if "audit" in k or "policy change" in k:
        return "AU-6"

    if audit_key.startswith("Se"):
        return "AC-6"

    if any(x in k for x in ["defender", "realtime", "protection"]):
        return "SI-3"

    if "integrity" in k:
        return "SI-7"

    if any(x in k for x in ["registry", "policy", "setting"]):
        return "CM-6"

    if any(x in k for x in ["network", "ip", "dns"]):
        return "SC-7"

    return ""


# -------------------------
# NIST API Lookup (with cache)
# -------------------------
def lookup_nist_api(audit_key: str) -> str:
    # ✅ 1. persistent cache
    if audit_key in NIST_CACHE:
        return NIST_CACHE[audit_key]

    result = infer_nist_control(audit_key)

    try:
        url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
        params = {"keywordSearch": audit_key}

        response = requests.get(url, params=params, timeout=5)

        if response.status_code == 200:
            data = response.json()
            if data.get("totalResults", 0) > 0:
                result = infer_nist_control(audit_key)

    except Exception:
        pass

    # ✅ save result
    NIST_CACHE[audit_key] = result
    save_cache(NIST_CACHE)

    return result


# -------------------------
# Coverage Summary
# -------------------------
def print_coverage_summary(dataset):
    total = len(dataset)

    cis_mapped = sum(1 for r in dataset if r.get("cis_control"))
    nist_mapped = sum(1 for r in dataset if r.get("nist_800_53r5"))

    print("\n===== COVERAGE SUMMARY =====")
    print(f"Total Controls: {total}")
    print(f"CIS Coverage: {cis_mapped}/{total} ({(cis_mapped/total)*100:.1f}%)")
    print(f"NIST Coverage: {nist_mapped}/{total} ({(nist_mapped/total)*100:.1f}%)")


# -------------------------
# CIS extraction
# -------------------------
def extract_cis_from_attrs(attrs: dict) -> str:
    ref = attrs.get("Reference", "")

    if "|" in ref:
        return ref.split("|")[0].strip()

    return ""


# -------------------------
# Input Handling
# -------------------------
def ask_for_files() -> Tuple[List[str], Dict[str, Optional[str]]]:
    raw = input("Enter file(s) and options: ").strip().replace("\\", "/")
    tokens = shlex.split(raw)

    files, options = [], {}
    i = 0

    while i < len(tokens):
        token = tokens[i].rstrip(',')

        if token.startswith('--'):
            if token in ('--export-excel', '--export-json'):
                options[token] = 'true'
            elif token == '--output-file':
                i += 1
                options[token] = tokens[i] if i < len(tokens) else None
            else:
                logging.warning(f"Unsupported option ignored: {token}")
        else:
            files.append(str(Path(token)))

        i += 1

    return files, options


# -------------------------
# Argument Parsing
# -------------------------
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit Index Extractor")
    parser.add_argument('files', nargs='*')
    parser.add_argument('--export-excel', action='store_true')
    parser.add_argument('--export-json', action='store_true')
    parser.add_argument('--output-file')
    return parser.parse_args()


def resolve_inputs(args):
    if args.files:
        return args

    files, options = ask_for_files()
    if not files:
        raise ValueError("No file paths provided.")

    args.files = files
    args.export_excel |= options.get('--export-excel') == 'true'
    args.export_json |= options.get('--export-json') == 'true'
    args.output_file = options.get('--output-file') or args.output_file

    return args


# -------------------------
# File Processing
# -------------------------
def load_file(path: Path) -> str:
    if not path.exists():
        raise FileNotFoundError(path)

    return path.read_text(encoding='utf-8', errors='ignore')


# -------------------------
# Block Parsing
# -------------------------
def parse_block_to_dict(block: str) -> Dict[str, str]:
    attributes = {}
    current_key = None
    buffer = []

    for line in block.splitlines():
        line = line.strip()
        if not line:
            continue

        match = KEY_VALUE_PATTERN.match(line)

        if match:
            if current_key:
                attributes[current_key] = " ".join(buffer).strip(' "\'')

            current_key = match.group(1).lower()
            buffer = [match.group(2).strip()]

        elif current_key:
            buffer.append(line)

    if current_key:
        attributes[current_key] = " ".join(buffer).strip(' "\'')

    return {k: re.sub(r'\s+\]\s*$', '', v) for k, v in attributes.items()}


# -------------------------
# Index Extraction
# -------------------------
def extract_regex_index_id(description: str) -> str:
    if not description:
        return "N/A"

    match = INDEX_PATTERN_1.search(description)
    if match:
        return match.group(1)

    match = INDEX_PATTERN_2.search(description)
    if match:
        return match.group(1)

    match = SIMPLE_PREFIX_PATTERN.match(description)
    if match:
        parts = match.group(1).split('.')
        return parts[-1] if len(parts) > 1 else parts[0]

    return "N/A"


# -------------------------
# ✅ KEY FUNCTION (FIXED + ENHANCED)
# -------------------------
def calculate_audit_key_name(block_dict: Dict[str, str], description: str) -> str:
    full_text = " ".join(block_dict.values())

    # =====================================================
    # ✅ 0. NEW HIGH-PRIORITY DETECTION (YOUR REQUEST)
    # =====================================================

    # ✅ USER_RIGHTS detection
    if "secedit" in full_text.lower() and "user_rights" in full_text.lower():
        return "USER_RIGHTS"

    # ✅ Services (registry path)
    if "CurrentControlSet\\Services" in full_text:
        return "Service"

    # ✅ ASR Rules
    if "Windows Defender Exploit Guard\\ASR\\Rules" in full_text:
        return "ASR Rules"

    # =====================================================
    # ✅ 1. Registry: PSObject.Properties['X']
    # =====================================================
    match = re.search(
        r"Properties\[['\"]([A-Za-z0-9_-]+)['\"]\]",
        full_text,
        re.IGNORECASE
    )
    if match:
        return match.group(1)
    # =====================================================
    # ✅ 2. Get-ItemProperty).Property extraction
    # =====================================================
    match = re.search(
        r"Get-ItemProperty[^)]*\)\.\s*([A-Za-z0-9_]+)",
        full_text,
        re.IGNORECASE
    )
    if match:
        return match.group(1)

    # =====================================================
    # ✅ 3. Generic ).Property extraction (handles $noutput cases)
    # =====================================================
    match = re.search(
        r"\(Get-ItemProperty[^)]*\)\.\s*([A-Za-z0-9_]+)",
        full_text
    )
    if match:
        return match.group(1)

    # =====================================================
    # ✅ 4. Registry: $p.'X'
    # =====================================================
    match = re.search(
        r"\.\s*['\"]([A-Za-z0-9_-]+)['\"]",
        full_text
    )
    if match:
        return match.group(1)

    # =====================================================
    # ✅ 5. Secedit (ALL cases)
    # =====================================================
    match = re.search(
        r"-match\s+['\"]\^\s*([A-Za-z0-9_]+).*?=",
        full_text,
        re.IGNORECASE
    )
    if match:
        return match.group(1)

    # =====================================================
    # ✅ 6. auditpol
    # =====================================================
    match = re.search(
        r"subcategory:'([^']+)'",
        full_text,
        re.IGNORECASE
    )
    if match:
        return "".join(w.capitalize() for w in match.group(1).split())

    # =====================================================
    # ✅ 7. net accounts
    # =====================================================
    if "password history" in full_text.lower():
        return "EnforcePasswordHistory"

    # =====================================================
    # ✅ 8. ComputerInfo pipeline
    # =====================================================
    match = re.search(
        r"Get-ComputerInfo.*?Select-Object\s+([A-Za-z0-9_,\s]+)",
        full_text,
        re.IGNORECASE
    )
    if match:
        props = [p.strip() for p in match.group(1).split(",")]
        if props:
            return f"ComputerInfo_{props[-1]}"

    # =====================================================
    # ✅ 9. Known commands
    # =====================================================
    if "Get-NetIPConfiguration" in full_text:
        return "NetIPConfiguration"

    # =====================================================
    # ✅ 10. Generic Get-*
    # =====================================================
    match = re.search(r"\bGet-([A-Za-z0-9]+)", full_text)
    if match:
        return match.group(1)

    # =====================================================
    # ✅ 11. Description-based
    # =====================================================
    match = re.search(
        r"Ensure\s+([A-Za-z ]+?)\s+is\s+set",
        description,
        re.IGNORECASE
    )
    if match:
        return "".join(w.capitalize() for w in match.group(1).split())

    # =====================================================
    # ✅ FINAL fallback
    # =====================================================
    
    combined = (description + " " + full_text).lower()
    for keyword in KNOWN_KEYWORDS:
        if keyword in combined:
            return keyword

    return "UNRESOLVED_AUDIT_KEY"


def classify_audit_key(audit_key: str, full_text: str) -> str:
    text_upper = full_text.upper()

    # -------------------------
    # USER RIGHTS
    # -------------------------
    if "USER_RIGHTS" in text_upper or audit_key.startswith("Se"):
        return "USER_RIGHTS"

    # -------------------------
    # Services
    # -------------------------
    if "CurrentControlSet\\Services" in full_text:
        return "Service"

    # -------------------------
    # ASR Rules
    # -------------------------
    if "Windows Defender Exploit Guard\\ASR\\Rules" in full_text:
        return "ASR Rules"

    # -------------------------
    # Audit Policy
    # -------------------------
    if "auditpol" in full_text.lower():
        return "AuditPolicy"

    # -------------------------
    # Security Policy (secedit)
    # -------------------------
    if audit_key in {
        "MaximumPasswordAge", "MinimumPasswordAge", "MinimumPasswordLength",
        "PasswordComplexity", "ClearTextPassword",
        "LockoutDuration", "LockoutBadCount", "ResetLockoutCount",
        "AllowAdministratorLockout"
    }:
        return "SecurityPolicy"

    # -------------------------
    # System Info
    # -------------------------
    if audit_key.startswith("ComputerInfo"):
        return "SystemInfo"

    # -------------------------
    # Network
    # -------------------------
    if audit_key == "NetIPConfiguration":
        return "Network"

    # -------------------------
    # Registry fallback
    # -------------------------
    if "Get-ItemProperty" in full_text:
        return "Registry"

    return "Other"


def process_audit_to_index(text: str) -> List[Dict[str, str]]:
    dataset = []

    matches = list(CUSTOM_BLOCK_PATTERN.finditer(text))
    total = len(matches)

    if total == 0:
        return dataset

    # ✅ Step 1: Pre-collect keys
    audit_keys = []
    parsed_blocks = []

    for match in matches:
        block = match.group(1)
        attrs = parse_block_to_dict(block)

        if not attrs:
            continue

        desc = attrs.get("description", "")

        audit_key = calculate_audit_key_name(attrs, desc)

        audit_key = normalize_audit_key(
            audit_key,
            " ".join(attrs.values())
        )

        audit_keys.append(audit_key)
        parsed_blocks.append((attrs, desc, audit_key))

    # ✅ Step 2: Batch NIST lookup
    nist_lookup_table = batch_lookup_nist(set(audit_keys))

    # ✅ Step 3: Build dataset
    count = 0

    for attrs, desc, audit_key in parsed_blocks:
        count += 1

        if count % 10 == 0 or count == total:
            print(f"Processing {count}/{total} ({int((count/total)*100)}%)")

        classification = classify_audit_key(
            audit_key,
            " ".join(attrs.values())
        )

        nist_control = nist_lookup_table.get(audit_key, "")

        cis_control = extract_cis_from_attrs(attrs)

        nist_family = get_control_family(nist_control)
        nist_family_name = get_control_family_name(nist_family)

        record = {
            "index_id": extract_regex_index_id(desc),
            "audit_key_name": audit_key,
            "category": classification,
            "cis_control": cis_control,
            "nist_800_53r5": nist_control,
            "nist_family": nist_family,
            "nist_family_name": nist_family_name,
            **attrs,
        }

        dataset.append(record)

    return dataset


# -------------------------
# Export Helpers
# -------------------------
def normalize_output_path(input_path: Path, output_file: Optional[str], ext: str) -> Path:
    if output_file:
        base = Path(output_file)
        return base.with_name(f"{base.stem}_{input_path.stem}{ext}")
    return input_path.with_suffix(ext)


def build_baseline_controls(dataset: List[Dict]) -> List[Dict]:
    baseline = {}

    for r in dataset:
        key = r.get("audit_key_name")

        if not key:
            continue

        # ✅ keep most complete version
        existing = baseline.get(key)

        if not existing or (
            len(str(r.get("nist_800_53r5", ""))) >
            len(str(existing.get("nist_800_53r5", "")))
        ):
            baseline[key] = {
                "audit_key_name": key,
                "category": r.get("category", ""),
                "cis_control": r.get("cis_control", ""),
                "nist_800_53r5": r.get("nist_800_53r5", ""),
                "nist_family": r.get("nist_family", ""),
                "nist_family_name": r.get("nist_family_name", ""),
            }

    return list(baseline.values())


def export_excel(data: List[Dict], path: Path):
    df = pd.DataFrame(data)

    if df.empty:
        logging.warning("No data to export.")
        return

    # ✅ Main dataset formatting
    df.columns = [str(c).replace('_', ' ').title() for c in df.columns]

    front = ["Index Id", "Audit Key Name"]
    front_exist = [c for c in front if c in df.columns]
    others = [c for c in df.columns if c not in front_exist]

    df = df[front_exist + others]

    # ✅ Build Baseline Controls sheet
    baseline_data = build_baseline_controls(data)
    baseline_df = pd.DataFrame(baseline_data)

    if not baseline_df.empty:
        baseline_df.columns = [str(c).replace('_', ' ').title() for c in baseline_df.columns]

        front2 = ["Audit Key Name", "Category", "Cis Control", "Nist 800-53R5"]
        front2_exist = [c for c in front2 if c in baseline_df.columns]
        others2 = [c for c in baseline_df.columns if c not in front2_exist]

        baseline_df = baseline_df[front2_exist + others2]
        baseline_df = baseline_df.sort_values(by=["Category", "Audit Key Name"])

    # ✅ Write BOTH sheets
    with pd.ExcelWriter(path, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name='Indexed Compliance Map', index=False)

        if not baseline_df.empty:
            baseline_df.to_excel(writer, sheet_name='Baseline Controls', index=False)

    logging.info(f"Excel exported → {path}")


def export_json(data: List[Dict], path: Path):
    path.write_text(json.dumps(data, indent=2), encoding='utf-8')
    logging.info(f"JSON exported → {path}")


# -------------------------
# Main
# -------------------------
def main():
    try:
        args = resolve_inputs(parse_args())
    except ValueError as e:
        logging.error(e)
        return

    if not args.export_excel and not args.export_json:
        args.export_excel = True

    for file_str in args.files:
        path = Path(file_str)

        if not path.exists():
            logging.error(f"File not found: {path}")
            continue

        logging.info(f"Processing: {path.name}")

        try:
            text = load_file(path)
        except Exception:
            logging.exception(f"Failed to read file: {path}")
            continue

        try:
            dataset = process_audit_to_index(text)
        except Exception:
            logging.exception(f"Failed processing {path}")
            continue

        if not dataset:
            logging.warning(f"No custom_item blocks in {path.name}")
            continue

        # ✅ Coverage report
        print_coverage_summary(dataset)

        # ✅ Export
        if args.export_excel:
            try:
                export_excel(dataset, normalize_output_path(path, args.output_file, ".xlsx"))
            except Exception:
                logging.exception("Excel export failed")

        if args.export_json:
            try:
                export_json(dataset, normalize_output_path(path, args.output_file, ".json"))
            except Exception:
                logging.exception("JSON export failed")


if __name__ == "__main__":
    main()