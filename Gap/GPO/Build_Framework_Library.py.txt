import argparse
from pathlib import Path
import pandas as pd

# Define paths matching your local development workspace
BASE_DIR = Path(r"C:\PySC")
CATALOG_PATH = BASE_DIR / "sp800-53r5-control-catalog.xlsx"
CSF_PATH = BASE_DIR / "csf-pf-to-sp800-53r5-mappings.xlsx"
ISO_PATH = BASE_DIR / "sp800-53r5-to-iso-27001-mapping-2022-OLIR-2023-10-12-UPDATED.xlsx"
OUTPUT_PATH = BASE_DIR / "Framework_Library.xlsx"


def clean_control_id(val):
    """Standardizes NIST IDs (e.g., AC-1, ac-1, AC-01) to maximize join matching accuracy."""
    if pd.isna(val):
        return ""
    return str(val).strip().upper()


def find_nist_column(df, filename_hint=""):
    """Scans column names to locate the NIST SP 800-53 Control Identifier."""
    possible_names = [
        "CONTROL IDENTIFIER",
        "CONTROL ID",
        "NIST ID",
        "SP 800-53 REV 5",
        "SP 800-53 ID",
        "NIST SP 800-53 REV. 5 CONTROL",
        "SP 800-53 CONTROL",
    ]
    for col in df.columns:
        c_clean = str(col).strip().upper()
        if c_clean in possible_names or "800-53" in c_clean or "NIST" in c_clean:
            print(f"   [Match Found] Mapped anchor column '{col}' for {filename_hint}")
            return col
    
    # Secure fallback to index 0 safely if columns exist
    if len(df.columns) > 0:
        print(f"   [Fallback] Using first column '{df.columns[0]}' for {filename_hint}")
        return df.columns[0]
    raise ValueError(f"The loaded sheet data grid for {filename_hint} has 0 columns.")


def read_smart_sheet(file_path: Path, sheet_keywords=None):
    """
    Inspects workbook tabs and loads the best target sheet. Bypasses raw 
    introductory tabs if keywords match.
    """
    if sheet_keywords is None:
        sheet_keywords = ["MAPPING", "TABLE", "CATALOG", "SP800", "CSF"]
        
    excel_file = pd.ExcelFile(file_path)
    sheet_names = excel_file.sheet_names
    
    # Try to find a worksheet tab matching keywords
    target_sheet = sheet_names[0]
    for sheet in sheet_names:
        for kw in sheet_keywords:
            if kw in sheet.upper() and "INTRO" not in sheet.upper() and "README" not in sheet.upper():
                target_sheet = sheet
                break
                
    print(f" -> Accessing sheet tab: '{target_sheet}' inside {file_path.name}")
    # Read the data, slipping down header if an empty first row is present
    df = pd.read_excel(file_path, sheet_name=target_sheet)
    
    # Clean out completely empty spacer rows or columns
    df.dropna(how="all", axis=0, inplace=True)
    df.dropna(how="all", axis=1, inplace=True)
    return df


def build_framework_library():
    print("=======================================================")
    print("         BUILDING UNIFIED COMPLIANCE FRAMEWORK         ")
    print("=======================================================")

    # 1. Verify existence of source files
    for path in [CATALOG_PATH, CSF_PATH, ISO_PATH]:
        if not path.exists():
            raise FileNotFoundError(f"Missing mandatory mapping dependency file: {path}")

    # 2. Ingest the Base NIST 800-53 Rev 5 Catalog
    print(f"\n1. Loading main control catalog...")
    df_catalog = read_smart_sheet(CATALOG_PATH, ["CATALOG", "SP 800-53", "CONTROLS"])
    nist_col_cat = find_nist_column(df_catalog, "Catalog")
    df_catalog["Join_Anchor"] = df_catalog[nist_col_cat].apply(clean_control_id)

    # 3. Ingest and group CSF Mappings
    print(f"\n2. Loading CSF Profile Mappings...")
    df_csf = read_smart_sheet(CSF_PATH, ["MAPPING", "CSF", "TABLE"])
    nist_col_csf = find_nist_column(df_csf, "CSF Mapping")
    df_csf["Join_Anchor"] = df_csf[nist_col_csf].apply(clean_control_id)

    # 4. Ingest and group ISO 27001:2022 Mappings
    print(f"\n3. Loading ISO 27001 OLIR Mappings...")
    df_iso = read_smart_sheet(ISO_PATH, ["OLIR", "MAPPING", "TABLE", "ISO"])
    nist_col_iso = find_nist_column(df_iso, "ISO Mapping")
    df_iso["Join_Anchor"] = df_iso[nist_col_iso].apply(clean_control_id)

    # 5. Execute Relational Left Joins (Preserving every master NIST catalog row)
    print("\n4. Synchronizing and joining frameworks via NIST control anchors...")

    # Merge CSF Context
    library_df = pd.merge(df_catalog, df_csf.drop(columns=[nist_col_csf], errors='ignore'), 
                          on="Join_Anchor", how="left", suffixes=('', '_CSF'))

    # Merge ISO Context
    library_df = pd.merge(library_df, df_iso.drop(columns=[nist_col_iso], errors='ignore'), 
                          on="Join_Anchor", how="left", suffixes=('', '_ISO'))

    # Drop internal working helper column
    library_df.drop(columns=["Join_Anchor"], inplace=True, errors='ignore')

    # 6. Export Unified Framework Matrix to Excel
    print(f"\n5. Exporting matrix rows out to disk...")
    with pd.ExcelWriter(OUTPUT_PATH, engine="openpyxl") as writer:
        library_df.to_excel(writer, sheet_name="Master_Control_Library", index=False)
        
        # Color code master tab sheet Green
        ws = writer.sheets["Master_Control_Library"]
        ws.sheet_properties.tabColor = "27AE60"

        # Keep original raw mappings accessible as back tabs
        df_catalog.drop(columns=["Join_Anchor"], errors='ignore').to_excel(writer, sheet_name="Raw_800_53_Catalog", index=False)
        df_csf.drop(columns=["Join_Anchor"], errors='ignore').to_excel(writer, sheet_name="Raw_CSF_Mappings", index=False)
        df_iso.drop(columns=["Join_Anchor"], errors='ignore').to_excel(writer, sheet_name="Raw_ISO_Mappings", index=False)

    print("=======================================================")
    print(f" SUCCESS: Unified Library written to: {OUTPUT_PATH}")
    print("=======================================================")


if __name__ == "__main__":
    build_framework_library()
