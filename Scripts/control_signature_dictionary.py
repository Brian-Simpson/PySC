import pandas as pd
import re
import os

# =====================================================
# CONFIG
# =====================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AUDIT_FOLDER = os.path.join(BASE_DIR, "audits")
OUTPUT_FILE = os.path.join(BASE_DIR, "control_signatures.xlsx")

# =====================================================
# EXTRACT POWERSHELL (KEEP RAW CASE)
# =====================================================
def extract_powershell(block):
    """
    ✅ FINAL: deterministic extraction using index slicing
    """

    # Locate the powershell_args label
    idx = block.lower().find("powershell_args")

    if idx == -1:
        return ""

    sub = block[idx:]

    # Find first quote AFTER colon
    colon_idx = sub.find(":")
    if colon_idx == -1:
        return ""

    sub = sub[colon_idx + 1:]

    first_quote = sub.find('"')
    if first_quote == -1:
        return ""

    sub = sub[first_quote + 1:]

    # Find last quote BEFORE end of custom_item block
    last_quote = sub.rfind('"')
    if last_quote == -1:
        return ""

    text = sub[:last_quote]

    # Cleanup
    text = text.replace("\n", " ").replace("\r", " ")
    text = re.sub(r'\s+', ' ', text).strip()

    return text


# =====================================================
# EXTRACT NIST
# =====================================================
def extract_nist(block):

    match = re.search(r'reference\s*:\s*"(.*?)"', block)

    if not match:
        return None

    ref = match.group(1)

    m = re.search(r'\|(.*?)$', ref)

    return m.group(1).upper() if m else None


# =====================================================
# EXTRACT DESCRIPTION
# =====================================================
def extract_description(block):

    match = re.search(r'description\s*:\s*"(.*?)"', block)

    return match.group(1) if match else None


# =====================================================
# ✅ FINAL SIGNATURE EXTRACTION
# =====================================================

def extract_signatures(signal):

    results = []

    if not signal:
        return results

    # ========================
    # PASSWORD / GPO KEYS
    # ========================
    matches = re.findall(r'\^?(MinimumPasswordLength|MaximumPasswordAge|MinimumPasswordAge|Lockout\w+)\s*=', signal)
    for m in matches:
        results.append((m.lower(), m.replace("Password", " Password")))

    # ========================
    # REGISTRY KEYS
    # ========================
    reg = re.findall(r"\['([A-Za-z0-9]+)'\]", signal)
    for r in reg:
        results.append((r.lower(), r))

    # ========================
    # DOT PROPERTIES
    # ========================
    dot = re.findall(r'\.(\w+)', signal)
    for d in dot:
        if len(d) > 5:
            results.append((d.lower(), d))

    # ========================
    # NET ACCOUNTS
    # ========================
    if "net accounts" in signal.lower():
        results.append(("net accounts", "Password Policy"))

    # ========================
    # AUDITPOL
    # ========================
    audit = re.findall(r"subcategory:'([^']+)'", signal)
    for a in audit:
        results.append((f"auditpol {a.lower()}", f"Audit {a}"))

    # ========================
    # COMMANDS
    # ========================
    if "get-computerinfo" in signal.lower():
        results.append(("get-computerinfo", "System Info"))

    return results


# =====================================================
# MAIN
# =====================================================
print("📂 Building control signature dictionary...")

records = []

for file in os.listdir(AUDIT_FOLDER):

    if not file.lower().endswith(".audit"):
        continue

    path = os.path.join(AUDIT_FOLDER, file)

    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    blocks = re.findall(r"<custom_item>(.*?)</custom_item>", content, re.DOTALL)

    for b in blocks:

        signal = extract_powershell(b)
        desc = extract_description(b)
        nist = extract_nist(b)

        # ✅ DEBUG FIRST FEW
        if len(records) < 5:
            print("\nDEBUG SIGNAL:")
            print(signal[:200])


        sigs = extract_signatures(signal)

        for pattern, signal_name in sigs:
            records.append({
                "Pattern": pattern,
                "Signal": signal_name,
                "NIST_Control_ID": nist,
                "Source_Control": desc,
                "Audit_File": file
            })


# =====================================================
# VALIDATE OUTPUT
# =====================================================
if not records:
    print("❌ No signatures extracted — check DEBUG above")
    exit()

df = pd.DataFrame(records).drop_duplicates()

df['Pattern'] = df['Pattern'].str.lower()
df['Signal'] = df['Signal'].str.strip()

print(f"\n✅ Extracted {len(df)} signatures")

# =====================================================
# EXPORT
# =====================================================
with pd.ExcelWriter(OUTPUT_FILE, engine='openpyxl') as writer:
    df.to_excel(writer, sheet_name='signatures', index=False)

print(f"✅ Created → {OUTPUT_FILE}")