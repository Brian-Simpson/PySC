import pandas as pd
import re
import os

# =====================================================
# CONFIG
# =====================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

NIST_FILE = os.path.join(BASE_DIR, "nist_master_combined.xlsx")
AUDIT_FOLDER = os.path.join(BASE_DIR, "audits")

# =====================================================
# SIGNATURE MAP (BASED ON REAL WINDOWS KEYS)
# =====================================================
SIGNATURE_MAP = {

    # IA-5
    "minimumpasswordlength": "IA-5",
    "maximumpasswordage": "IA-5",
    "minimumpasswordage": "IA-5",
    "net accounts": "IA-5",

    # AC-7
    "lockoutthreshold": "AC-7",
    "lockoutduration": "AC-7",
    "reset account lockout": "AC-7",

    # CM-8
    "currentbuild": "CM-8",
    "installationtype": "CM-8",
    "get-computerinfo": "CM-8",

    # AU-3
    "audit": "AU-3"
}

# =====================================================
# HELPERS
# =====================================================
def normalize_nist(control):
    if not control:
        return None
    return re.split(r'\(', str(control).upper())[0]

def extract_field(block, field):
    pattern = rf"{field}\s*:\s*(\".*?\"|\S+)"
    match = re.search(pattern, block, re.DOTALL)
    if match:
        return match.group(1).replace('"', '').strip()
    return None

# =====================================================
# ✅ CRITICAL FIX — POWERHELL EXTRACTION
# =====================================================
def extract_signal(block):
    """
    Extract PowerShell safely using QUOTE-BOUND method
    """

    match = re.search(r'powershell_args\s*:\s*"(.*?)"\s*(?:\n|$)', block, re.DOTALL)

    if not match:
        return ""

    text = match.group(1).lower()

    # Normalize whitespace
    text = re.sub(r'\s+', ' ', text)

    return text.strip()

# =====================================================
# MATCHING
# =====================================================
def match_signature(signal):

    if not signal:
        return None, "None"

    s = signal.replace(" ", "")

    for key, control in SIGNATURE_MAP.items():
        k = key.replace(" ", "")

        if k in s:
            return control, "Signature"

    return None, "None"

def validate(control_id, valid_controls):

    if not control_id:
        return "INVALID"

    return "VALID" if control_id in valid_controls else "INVALID"

def extract_vendor_nist(ref):
    if not ref:
        return None
    match = re.search(r'\|(.*?)$', ref)
    return normalize_nist(match.group(1)) if match else None

# =====================================================
# LOAD NIST MASTER
# =====================================================
print("📂 Loading NIST master...")

nist_df = pd.read_excel(NIST_FILE, sheet_name="Summary", engine="openpyxl")
nist_df['NIST_Control_ID'] = nist_df['NIST_Control_ID'].apply(normalize_nist)
nist_controls = set(nist_df['NIST_Control_ID'].dropna())

print(f"✅ Loaded {len(nist_controls)} NIST controls")

# =====================================================
# PARSE AUDIT
# =====================================================
print("📂 Parsing .audit files...")

records = []

for file in os.listdir(AUDIT_FOLDER):

    if not file.lower().endswith(".audit"):
        continue

    path = os.path.join(AUDIT_FOLDER, file)

    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    blocks = re.findall(r"<custom_item>(.*?)</custom_item>", content, re.DOTALL)

    for b in blocks:

        desc = extract_field(b, "description")
        ref = extract_field(b, "reference")

        signal = extract_signal(b)
        vendor = extract_vendor_nist(ref)

        # ✅ DEBUG (keep for first run)
        # print("DEBUG SIGNAL:", signal[:120])

        nist_id, match_type = match_signature(signal)

        records.append({
            "Audit_Name": file,
            "Control_Text": desc,
            "Signal_Text": signal,
            "NIST_Control_ID": nist_id,
            "Vendor_NIST": vendor,
            "Match_Type": match_type
        })

audit_df = pd.DataFrame(records)

print(f"✅ Parsed {len(audit_df)} audit controls")

# =====================================================
# DEBUG VIEW
# =====================================================
print("\n🔎 SAMPLE SIGNALS:")
print(audit_df[['Control_Text', 'Signal_Text']].head(10))

# =====================================================
# VALIDATION
# =====================================================
audit_df['Validation_Status'] = audit_df['NIST_Control_ID'].apply(
    lambda x: validate(x, nist_controls)
)

# =====================================================
# SAVE
# =====================================================
print("💾 Updating NIST master...")

with pd.ExcelWriter(NIST_FILE, engine='openpyxl', mode='a', if_sheet_exists='replace') as writer:
    audit_df.to_excel(writer, sheet_name='inclusive', index=False)

# =====================================================
# SUMMARY
# =====================================================
print("\n📊 SUMMARY")
print("Total Controls:", len(audit_df))
print("Validated:", len(audit_df[audit_df['Validation_Status']=="VALID"]))
print("Invalid:", len(audit_df[audit_df['Validation_Status']=="INVALID"]))
print("Signature Matches:", len(audit_df[audit_df['Match_Type']=="Signature"]))

print("\n✅ COMPLETE")
import pandas as pd
import re
import os

# =====================================================
# CONFIG
# =====================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

NIST_FILE = os.path.join(BASE_DIR, "nist_master_combined.xlsx")
AUDIT_FOLDER = os.path.join(BASE_DIR, "audits")
SIGNATURE_FILE = os.path.join(BASE_DIR, "control_signatures.xlsx")

# =====================================================
# LOAD SIGNATURE DICTIONARY
# =====================================================
print("📂 Loading signature dictionary...")

sig_df = pd.read_excel(SIGNATURE_FILE, sheet_name="signatures", engine="openpyxl")

# Normalize
sig_df['Signature'] = sig_df['Signature'].str.lower().fillna("")
sig_df['Regex'] = sig_df['Regex'].str.lower().fillna("")
sig_df['NIST_Control_ID'] = sig_df['NIST_Control_ID'].str.upper()

print(f"✅ Loaded {len(sig_df)} signatures")

# =====================================================
# HELPERS
# =====================================================
def normalize_nist(control):
    if not control:
        return None
    return re.split(r'\(', str(control).upper())[0]

def extract_field(block, field):
    pattern = rf"{field}\s*:\s*(\".*?\"|\S+)"
    match = re.search(pattern, block, re.DOTALL)
    if match:
        return match.group(1).replace('"', '').strip()
    return None

def extract_signal(block):
    """
    Extract PowerShell content safely
    """
    match = re.search(r'powershell_args\s*:\s*"(.*?)"', block, re.DOTALL)

    if not match:
        return ""

    text = match.group(1).lower()
    text = re.sub(r'\s+', ' ', text)

    return text

# =====================================================
# MATCH USING SIGNATURE + REGEX
# =====================================================
def match_from_dictionary(signal):

    if not signal:
        return None, "None"

    for _, row in sig_df.iterrows():

        sig = row['Signature']
        regex = row['Regex']
        nist = row['NIST_Control_ID']

        # ✅ Direct signature match
        if sig and sig in signal:
            return nist, "Signature"

        # ✅ Regex match
        if regex:
            try:
                if re.search(regex, signal):
                    return nist, "Regex"
            except:
                continue

    return None, "None"

def validate(control_id, valid_controls):

    if not control_id:
        return "INVALID"

    return "VALID" if control_id in valid_controls else "INVALID"

def extract_vendor_nist(ref):
    if not ref:
        return None
    match = re.search(r'\|(.*?)$', ref)
    return normalize_nist(match.group(1)) if match else None

# =====================================================
# LOAD NIST MASTER
# =====================================================
print("📂 Loading NIST master...")

nist_df = pd.read_excel(NIST_FILE, sheet_name="Summary", engine="openpyxl")

nist_df['NIST_Control_ID'] = nist_df['NIST_Control_ID'].apply(normalize_nist)

nist_controls = set(nist_df['NIST_Control_ID'].dropna())

print(f"✅ Loaded {len(nist_controls)} NIST controls")

# =====================================================
# PARSE AUDIT FILES
# =====================================================
print("📂 Parsing .audit files...")

records = []

for file in os.listdir(AUDIT_FOLDER):

    if not file.lower().endswith(".audit"):
        continue

    path = os.path.join(AUDIT_FOLDER, file)

    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    blocks = re.findall(r"<custom_item>(.*?)</custom_item>", content, re.DOTALL)

    for b in blocks:

        desc = extract_field(b, "description")
        ref = extract_field(b, "reference")

        signal = extract_signal(b)
        vendor = extract_vendor_nist(ref)

        nist_id, match_type = match_from_dictionary(signal)

        records.append({
            "Audit_Name": file,
            "Control_Text": desc,
            "Signal_Text": signal,
            "NIST_Control_ID": nist_id,
            "Vendor_NIST": vendor,
            "Match_Type": match_type
        })

audit_df = pd.DataFrame(records)

print(f"✅ Parsed {len(audit_df)} audit controls")

# =====================================================
# DEBUG SAMPLE
# =====================================================
print("\n🔎 SAMPLE SIGNALS:")
print(audit_df[['Control_Text', 'Signal_Text']].head(10))

# =====================================================
# VALIDATION
# =====================================================
audit_df['Validation_Status'] = audit_df['NIST_Control_ID'].apply(
    lambda x: validate(x, nist_controls)
)

# =====================================================
# SAVE OUTPUT
# =====================================================
print("💾 Updating NIST master...")

with pd.ExcelWriter(NIST_FILE, engine='openpyxl', mode='a', if_sheet_exists='replace') as writer:
    audit_df.to_excel(writer, sheet_name='inclusive', index=False)

# =====================================================
# SUMMARY
# =====================================================
print("\n📊 SUMMARY")
print("Total Controls:", len(audit_df))
print("Validated:", len(audit_df[audit_df['Validation_Status']=="VALID"]))
print("Invalid:", len(audit_df[audit_df['Validation_Status']=="INVALID"]))
print("Signature Matches:", len(audit_df[audit_df['Match_Type']=="Signature"]))
print("Regex Matches:", len(audit_df[audit_df['Match_Type']=="Regex"]))

print("\n✅ COMPLETE: Signature dictionary engine active")
