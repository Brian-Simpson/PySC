import pandas as pd
import re
import os

# =====================================================
# CONFIG
# =====================================================
BASE_DIR = r"C:\PySC"

CATALOG_FILE = os.path.join(BASE_DIR, "sp800-53r5-control-catalog.xlsx")
CSF_FILE = os.path.join(BASE_DIR, "csf-pf-to-sp800-53r5-mappings.xlsx")
ISO_FILE = os.path.join(BASE_DIR, "sp800-53r5-to-iso-27001-mapping-2022-OLIR-2023-10-12-UPDATED.xlsx")

OUTPUT_FILE = os.path.join(BASE_DIR, "nist_master_combined.xlsx")

# =====================================================
# HELPERS
# =====================================================
def normalize_control_id(control):
    if pd.isnull(control):
        return None
    return re.split(r'\(', str(control).upper().strip())[0]

def extract_family(control_id):
    if pd.isnull(control_id):
        return None
    return str(control_id).split('-')[0]

def split_controls(value):
    if pd.isnull(value):
        return []
    return [v.strip().upper() for v in re.split(r'[,\n ]', str(value)) if v.strip()]

# =====================================================
# LOAD FILES
# =====================================================
print("📂 Loading files...")

catalog = pd.read_excel(CATALOG_FILE, engine="openpyxl")

# ================= CSF SMART LOAD =================
xlsx = pd.ExcelFile(CSF_FILE, engine="openpyxl")
print("📄 CSF Sheets:", xlsx.sheet_names)

csf = None

for sheet in xlsx.sheet_names:
    temp = pd.read_excel(xlsx, sheet_name=sheet)

    # skip tiny or empty sheets
    if temp.shape[0] < 20:
        continue

    cols = [str(c).lower() for c in temp.columns]

    # detect real mapping sheet
    if any("control" in c or "800" in c for c in cols):
        csf = temp
        print(f"✅ Using CSF sheet: {sheet}")
        break

if csf is None:
    raise Exception("❌ Could not find valid CSF sheet")

# ================= ISO LOAD =================
iso = pd.read_excel(ISO_FILE, engine="openpyxl")

print("✅ Files loaded")

# =====================================================
# CATALOG
# =====================================================
catalog.columns = [c.strip() for c in catalog.columns]

catalog = catalog.rename(columns={
    'Control Identifier': 'NIST_Control_ID',
    'Control (or Control Enhancement) Name': 'Control_Name',
    'Control Text': 'Description'
})

catalog['NIST_Control_ID'] = catalog['NIST_Control_ID'].apply(normalize_control_id)
catalog['Control_Family'] = catalog['NIST_Control_ID'].apply(extract_family)

catalog = catalog[
    ['NIST_Control_ID', 'Control_Name', 'Control_Family', 'Description']
].drop_duplicates()

print(f"✅ Catalog: {len(catalog)} controls")

# =====================================================
# CSF PARSE (FIXED)
# =====================================================
csf.columns = [c.strip() for c in csf.columns]

print("📋 CSF Columns:", csf.columns.tolist())

csf_control_col = None

for col in csf.columns:
    if "800" in col.lower() and "control" in col.lower():
        csf_control_col = col

if csf_control_col is None:
    print("⚠️ No exact control column match — using widest column")
    csf_control_col = csf.columns[-1]

csf_rows = []

for _, row in csf.iterrows():
    controls = split_controls(row[csf_control_col])

    for ctrl in controls:
        base = normalize_control_id(ctrl)

        if base:
            csf_rows.append({
                "NIST_Control_ID": base,
                "CSF_Function": row.get("Function"),
                "CSF_Category": row.get("Category"),
                "CSF_Subcategory": row.get("Subcategory")
            })

csf_expanded = pd.DataFrame(csf_rows)

if csf_expanded.empty:
    print("⚠️ CSF parsing produced no rows — check file")
else:
    csf_expanded = csf_expanded.drop_duplicates()

print(f"✅ CSF Expanded: {len(csf_expanded)} rows")

# =====================================================
# ISO PARSE (FIXED OLIR)
# =====================================================
iso.columns = [c.strip() for c in iso.columns]

print("📋 ISO Columns:", iso.columns.tolist())

iso_rows = []

for _, row in iso.iterrows():
    focal = row.get('Focal Document\nElement') or row.get('Focal Document Element')
    ref = row.get('Reference Document Element')

    if pd.isnull(focal) or pd.isnull(ref):
        continue

    # Extract NIST control IDs using regex
    matches = re.findall(r'[A-Z]{2,3}-\d+', str(focal))

    for m in matches:
        iso_rows.append({
            "NIST_Control_ID": normalize_control_id(m),
            "ISO_Control": str(ref).strip()
        })

iso_clean = pd.DataFrame(iso_rows)

if iso_clean.empty:
    print("⚠️ ISO parsing produced 0 rows — continuing without ISO")
else:
    iso_clean = iso_clean.drop_duplicates()

print(f"✅ ISO Parsed: {len(iso_clean)} rows")

# =====================================================
# MERGE
# =====================================================
print("🔗 Merging...")

merged = catalog.copy()

if not csf_expanded.empty:
    merged = merged.merge(csf_expanded, on='NIST_Control_ID', how='left')

if not iso_clean.empty:
    merged = merged.merge(iso_clean, on='NIST_Control_ID', how='left')

merged = merged.drop_duplicates()

print(f"✅ Merge complete: {len(merged)} rows")

# =====================================================
# AGGREGATE
# =====================================================
agg = merged.groupby('NIST_Control_ID').agg({
    'Control_Name': 'first',
    'Control_Family': 'first',
    'Description': 'first',
    'CSF_Function': lambda x: ', '.join(sorted(set(filter(pd.notnull, x)))),
    'CSF_Category': lambda x: ', '.join(sorted(set(filter(pd.notnull, x)))),
    'CSF_Subcategory': lambda x: ', '.join(sorted(set(filter(pd.notnull, x)))),
    'ISO_Control': lambda x: ', '.join(sorted(set(filter(pd.notnull, x))))
}).reset_index()

print(f"✅ Aggregated controls: {len(agg)}")

# =====================================================
# SAVE
# =====================================================
with pd.ExcelWriter(OUTPUT_FILE, engine='openpyxl') as writer:
    merged.to_excel(writer, sheet_name='Detailed', index=False)
    agg.to_excel(writer, sheet_name='Summary', index=False)

print(f"✅ SUCCESS → {OUTPUT_FILE}")