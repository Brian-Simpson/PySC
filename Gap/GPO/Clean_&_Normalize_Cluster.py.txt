import pandas as pd
import re
import os

# =====================================================
# CONFIG
# =====================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AUDIT_FOLDER = os.path.join(BASE_DIR, "audits")
OUTPUT_FILE = os.path.join(BASE_DIR, "control_signatures.xlsx")

print("📂 Building control signature dictionary...")
print(f"📂 Using folder: {AUDIT_FOLDER}")

# =====================================================
# EXTRACT FUNCTIONS
# =====================================================
def extract_powershell(block):
    idx = block.lower().find("powershell_args")
    if idx == -1:
        return ""

    sub = block[idx:]
    colon = sub.find(":")
    if colon == -1:
        return ""

    sub = sub[colon + 1:]
    first = sub.find('"')
    last = sub.rfind('"')

    if first == -1 or last == -1:
        return ""

    text = sub[first + 1:last]
    text = re.sub(r'\s+', ' ', text.replace("\n", " ").replace("\r", " ")).strip()

    return text

def extract_description(block):
    m = re.search(r'description\s*:\s*"(.*?)"', block)
    return m.group(1) if m else None

def extract_nist(block):
    m = re.search(r'reference\s*:\s*"(.*?)"', block)
    if not m:
        return None
    ref = m.group(1)
    c = re.search(r'\|(.*?)$', ref)
    return c.group(1).upper() if c else None

def extract_control_id(desc):
    if not desc:
        return "0.0000_MSWRK"

    num = re.search(r'\d+\.\d+', desc)
    grp = re.search(r'-\s*([A-Z]{3,})', desc)

    if num and grp:
        return f"{num.group(0)}_{grp.group(1)}"

    return "0.0000_MSWRK"

# =====================================================
# SIGNAL EXTRACTION
# =====================================================
def extract_signatures(signal):

    results = []
    s = signal.lower()

    # =====================================================
    # ✅ COMPUTER INFO
    # =====================================================
    if "get-computerinfo" in s:
        fields = re.findall(r'select-object\s+([^;]+)', signal, re.IGNORECASE)
        if fields:
            for c in fields[0].split(","):
                name = c.strip()
                if name:
                    results.append(
                        (f"computerinfo {name.lower()}", f"ComputerInfo {name}")
                    )

    # =====================================================
    # ✅ NET IP
    # =====================================================
    if "get-netipconfiguration" in s:
        if "server" in s:
            results.append(("netipconfiguration server", "NetIPConfiguration Server"))
        else:
            results.append(("netipconfiguration", "NetIPConfiguration"))

    # =====================================================
    # ✅ NET ACCOUNTS
    # =====================================================
    if "net accounts" in s:
        if "password history" in s:
            results.append(("netaccounts_passwordhistory", "Password History"))
        else:
            results.append(("netaccounts", "Password Policy"))

    # =====================================================
    # ✅ FORCE LOGOFF WHEN LOGON HOURS EXPIRE (FINAL FIX)
    # =====================================================
    if "forcelogoff" in s or "logon hours expire" in s or "enableforcedlogoff" in s:
        results.append((
            "forcelogoff",
            "Force Logoff When Logon Hours Expire"
        ))

    # =====================================================
    # ✅ AUDIT POLICY (CRITICAL - MUST BE BEFORE OTHER LOGIC)
    # =====================================================
    audit = re.findall(r"subcategory:'([^']+)'", signal, re.IGNORECASE)

    for a in set(audit):
        results.append((
            f"auditpol {a.lower()}",
            f"Audit {a}"
        ))

    # =====================================================
    # ✅ SECEDIT (PASSWORD / LOCKOUT)
    # =====================================================
    secedit = re.findall(
        r'(?i)(MinimumPasswordLength|MaximumPasswordAge|MinimumPasswordAge|'
        r'PasswordComplexity|ClearTextPassword|'
        r'LockoutDuration|LockoutBadCount|ResetLockoutCount|'
        r'AllowAdministratorLockout)',
        signal
    )
    for sct in set(secedit):
        results.append((sct.lower(), sct))

    # =====================================================
    # ✅ LOCAL USER
    # =====================================================
    if "get-localuser" in s:

        if "-501" in signal or "guest" in s:
            if "enabled" in s:
                results.append(("localuser_guest_enabled", "Guest Account Status"))
            if ".name" in s:
                results.append(("localuser_guest_name", "Guest Account Name"))

        if "-500" in signal:
            if "enabled" in s:
                results.append(("localuser_admin_enabled", "Administrator Account Status"))
            if ".name" in s:
                results.append(("localuser_admin_name", "Administrator Account Name"))

    # =====================================================
    # ✅ SERVICES
    # =====================================================
    if "get-service" in s or "win32_service" in s:

        name_match = re.search(r"-Name\s+'([^']+)'", signal)
        if not name_match:
            name_match = re.search(r"\{\$_.Name -eq '([^']+)'\}", signal)

        service_name = name_match.group(1) if name_match else "unknown"

        if "status" in s:
            results.append(
                (f"service_{service_name.lower()}_status", f"Service {service_name} Status")
            )

        elif "startmode" in s:
            results.append(
                (f"service_{service_name.lower()}_startmode", f"Service {service_name} StartMode")
            )

    # =====================================================
    # ✅ WINDOWS OPTIONAL FEATURES
    # =====================================================
    if "get-windowsoptionalfeature" in s:

        feature_match = re.search(r"-FeatureName\s+([A-Za-z0-9]+)", signal)
        if feature_match:
            feature = feature_match.group(1)

            if "state" in s:
                results.append((
                    f"feature_{feature.lower()}_state",
                    f"Feature {feature} State"
                ))

    # =====================================================
    # ✅ USER RIGHTS (Se*)
    # =====================================================
    rights = re.findall(r'\b(Se[A-Za-z0-9]+(?:Privilege|Right))\b', signal)
    for r in set(rights):
        results.append((r.lower(), f"UserRight {r}"))

    # =====================================================
    # ✅ STANDARD PROPERTY EXTRACTION
    # =====================================================
    dot_props = re.findall(r'\)\.(\w+)', signal)
    ps_props = re.findall(r"\['([A-Za-z0-9_]+)'\]", signal)

    # ✅ VARIABLE PROPERTY ACCESS
    var_props = re.findall(r'\$[a-zA-Z0-9_]+\.(\w+)', signal)

    # ✅ COMBINE FIRST (DO NOT FILTER YET)
    all_props = set(dot_props + ps_props + var_props)

    # =====================================================
    # ✅ GLOBAL FILTER (CRITICAL)
    # =====================================================
    IGNORE_PROPS = {
        "psobject",
        "properties",
        "value",
        "count",
        "length",
        "trim",
        "split",
        "replace",
        "toupper",
        "tolower",
        "foreach",
        "where",
        "name",
        "enabled",
        "status",
        "state",
        "sid",
    }

    # ✅ APPLY FILTER TO ALL PROPERTIES
    all_props = {
        p for p in all_props
        if p.lower() not in IGNORE_PROPS and len(p) > 3
    }

    # -----------------------------
    # ✅ LANMANSERVER ENUMERATION (NULL SESSION PIPES / SHARES)
    # -----------------------------
    if "lanmanserver" in s and "parameters" in s and "psobject.properties" in s:

        # Named Pipes
        if "pipes" in s:
            results.append(("nullsessionpipes", "Null Session Pipes"))

        # Shares (if encountered elsewhere)
        if "shares" in s:
            results.append(("nullsessionshares", "Null Session Shares"))


    # =====================================================
    # ✅ SPECIAL CASES
    # =====================================================

    # ✅ HARDENED PATHS (NETLOGON / SYSVOL)
    hardened = re.findall(r"\['\\\\\*\\(NETLOGON|SYSVOL)'\]", signal)
    for h in set(hardened):
        results.append((
            f"hardenedpath_{h.lower()}",
            f"Hardened Path {h}"
        ))

    # ✅ DEVICE CLASS GUID LISTS
    guid_list = re.findall(r"\{([0-9a-fA-F\-]{36})\}", signal)
    for g in set(guid_list):
        results.append((
            f"device_class_{g.lower()}",
            f"Device Class {g}"
        ))

    # ✅ ASR RULE GUIDS
    guid_props = re.findall(r"\['([0-9a-fA-F\-]{36})'\]", signal)


    # =====================================================
    # ✅ DEFENDER ENRICHMENT (FIX 4)
    # =====================================================
    is_defender_context = (
        "windows defender" in s or
        "exploit guard" in s or
        "mpengine" in s or
        "defender" in s
    )

    for p in all_props:

        p_lower = p.lower()

        if "enablenetworkprotection" in p_lower:
            results.append(("defender_network_protection", "Defender Network Protection"))

        elif "enablefilehashcomputation" in p_lower:
            results.append(("defender_file_hash", "Defender File Hash Computation"))

        elif "exploitguard_asr_rules" in p_lower:
            results.append(("defender_asr_rules_config", "Defender ASR Rules Configuration"))

        elif is_defender_context:
            results.append((p_lower, f"Defender {p}"))

        else:
            results.append((p_lower, p))

    # ✅ ASR GUID RULES (FINAL)
    for g in set(guid_props):
        results.append((
            f"asr_rule_{g.lower()}",
            f"ASR Rule {g}"
        ))

    # =====================================================
    # ✅ BULK PROPERTY ENUMERATION
    # =====================================================
    if "psobject.properties" in s and "foreach-object" in s:

        if "nullsessionshares" in s:
            results.append(("nullsessionshares", "Null Session Shares"))

        elif "nullsessionpipes" in s:
            results.append(("nullsessionpipes", "Null Session Pipes"))

        elif "allowedexactpaths" in s:
            results.append(("allowedexactpaths", "Allowed Exact Paths"))

        elif "allowedpaths" in s:
            results.append(("allowedpaths", "Allowed Paths"))


    # =====================================================
    # ✅ FINAL DYNAMIC REGISTRY ENUMERATION FIX
    # =====================================================
    if not results and "psobject.properties" in s:

        # Network access controls
        if "lanmanserver" in s and "parameters" in s:

            if "shares" in s or "nullsession" in s:
                results.append(("nullsessionshares", "Null Session Shares"))

            if "pipes" in s:
                results.append(("nullsessionpipes", "Null Session Pipes"))

        # LSA anonymous lookup
        if "lsa" in s and "anonymousnamelookup" in s:
            results.append(("anonymousnamelookup", "Anonymous Name Lookup"))

        # SecurePipeServers paths
        if "allowedexactpaths" in s:
            results.append(("allowedexactpaths", "Allowed Exact Paths"))

        if "allowedpaths" in s:
            results.append(("allowedpaths", "Allowed Paths"))

        # Fallback catch (last resort, deterministic)
        if not results:
            results.append(("dynamic_registry_values", "Dynamic Registry Values"))


    # =====================================================
    # ✅ RETURN
    # =====================================================
    return results

# =====================================================
# CLASSIFICATION
# =====================================================
def classify_pattern(p):

    if not p or p == "none":
        return "NO_DATA"

    if any(x in p for x in ["password", "lockout"]):
        return "CORE"

    if p.startswith("auditpol"):
        return "DERIVED"

    if p.startswith("computerinfo") or p.startswith("netip"):
        return "INFO"

    if p.startswith("se"):
        return "PRIVILEGE"

    if p.startswith("localuser"):
        return "CORE"

    return "UNCLASSIFIED"

# =====================================================
# GROUPING
# =====================================================
def group_signal(p):

    if not p:
        return "UNKNOWN"

    if p.startswith("computerinfo"):
        return "System Information"

    if p.startswith("netaccounts"):
        return "Password Policy"

    if p.startswith("auditpol"):
        return "Audit Policy"

    if p.startswith("netip"):
        return "Network Configuration"

    if p.startswith("se"):
        return "User Rights"

    if p.startswith("localuser"):
        return "Account Management"

    return "Other"

# =====================================================
# MAIN LOOP
# =====================================================
records = []
seen = set()

for file in os.listdir(AUDIT_FOLDER):

    if not file.endswith(".audit"):
        continue

    path = os.path.join(AUDIT_FOLDER, file)
    print(f"📄 Processing: {path}")

    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    blocks = re.findall(r"<custom_item>(.*?)</custom_item>", content, re.DOTALL)

    for b in blocks:

        desc = extract_description(b)
        nist = extract_nist(b)
        ctrl_id = extract_control_id(desc)
        signal = extract_powershell(b)

        # -----------------------------
        # ✅ USER_RIGHTS_POLICY
        # -----------------------------
        right_match = re.search(r'right_type\s*:\s*(Se\w+)', b)
        if right_match:
            r = right_match.group(1)
            records.append({
                "Control_ID": ctrl_id,
                "Pattern": r.lower(),
                "Signal": f"UserRight {r}",
                "NIST_Control_ID": nist,
                "Source_Control": desc,
                "Audit_File": file
            })
            continue

        # -----------------------------
        # ✅ ANONYMOUS SID
        # -----------------------------
        if "ANONYMOUS_SID_SETTING" in b:
            records.append({
                "Control_ID": ctrl_id,
                "Pattern": "anonymous_sid_translation",
                "Signal": "Anonymous SID Translation",
                "NIST_Control_ID": nist,
                "Source_Control": desc,
                "Audit_File": file
            })
            continue

        sigs = extract_signatures(signal)

        if sigs:
            for pattern, sig_name in sigs:

                key = (ctrl_id, pattern)

                if key not in seen:
                    seen.add(key)

                    records.append({
                        "Control_ID": ctrl_id,
                        "Pattern": pattern,
                        "Signal": sig_name,
                        "NIST_Control_ID": nist,
                        "Source_Control": desc,
                        "Audit_File": file
                    })

        else:
            records.append({
                "Control_ID": ctrl_id,
                "Pattern": "none",
                "Signal": "NO_SIGNAL_EXTRACTED",
                "NIST_Control_ID": nist,
                "Source_Control": desc,
                "Audit_File": file
            })

# =====================================================
# DATAFRAME
# =====================================================
df = pd.DataFrame(records)

df["Pattern"] = df["Pattern"].astype(str).str.lower().str.strip()
df["Signal"] = df["Signal"].astype(str).str.strip()

df["Classification"] = df["Pattern"].apply(classify_pattern)
df["Signal_Group"] = df["Pattern"].apply(group_signal)

# Duplicate tracking
df["_key"] = df["Control_ID"] + "|" + df["Pattern"]
df["Duplicate_Count"] = df["_key"].map(df["_key"].value_counts())
df["Is_Duplicate"] = df["Duplicate_Count"] > 1

# Coverage
coverage = df.groupby("Control_ID")["Pattern"].count()
print("\n📊 COVERAGE:\n", coverage.head(20))

# Save
df.drop(columns=["_key"]).to_excel(OUTPUT_FILE, index=False)

print(f"\n✅ Total Records: {len(df)}")
print(f"✅ Saved → {OUTPUT_FILE}")