import os
import re
import pandas as pd


def load_low_pass_descriptions(excel_paths, threshold=0.90):
    """Reads Excel files and extracts descriptions where Pass rate is < threshold."""
    low_pass_descriptions = set()

    for path in excel_paths:
        if not os.path.exists(path):
            print(f"Warning: File not found at {path}. Skipping...")
            continue

        try:
            # Load Excel sheet (assumes standard tabular format)
            df = pd.read_excel(path)

            # Standardize column names to fix case issues
            df.columns = [str(col).strip().lower() for col in df.columns]

            if "description" not in df.columns or "pass" not in df.columns:
                print(
                    f"Warning: 'Description' or 'Pass' column missing in {path}."
                )
                continue

            # Filter rows where Pass rate is below the threshold (e.g., 0.90 or 90%)
            # Handles both float (0.85) and percentage integers (85)
            def is_low_pass(val):
                try:
                    val_float = float(str(val).replace("%", "").strip())
                    if val_float < 1.0:
                        return val_float < threshold
                    return val_float < (threshold * 100)
                except ValueError:
                    return False

            filtered_df = df[df["pass"].apply(is_low_pass)]

            # Add unique descriptions to our set
            for desc in filtered_df["description"].dropna():
                low_pass_descriptions.add(str(desc).strip())

        except Exception as e:
            print(f"Error processing {path}: {e}")

    return low_pass_descriptions


def comment_audit_content(audit_text, low_pass_descriptions):
    """Parses audit text and comments out custom_item blocks matching low-pass descriptions."""
    # Regex pattern to capture individual <custom_item> ... </custom_item> blocks
    block_pattern = re.compile(
        r"(<custom_item>.*?</custom_item>)", re.DOTALL | re.IGNORECASE
    )

    def replace_block(match):
        block = match.group(1)

        # Extract the description field value inside the block
        # Handles single quotes, double quotes, and multi-line descriptions safely
        desc_match = re.search(
            r"description\s*:\s*[\"'](.*?)[\"']", block, re.IGNORECASE
        )

        if desc_match:
            audit_desc = desc_match.group(1).strip()

            # Check if this exact description matches our low-pass criteria
            if audit_desc in low_pass_descriptions:
                # Comment out every line of this block using '#'
                commented_block = "\n".join(
                    f"#{line}" for line in block.splitlines()
                )
                print(f"Commenting out item: {audit_desc}")
                return commented_block

        # Return original block unchanged if no match
        return block

    # Substitute matching blocks
    return block_pattern.sub(replace_block, audit_text)


if __name__ == "__main__":
    # Define paths to your maturity metrics spreadsheets
    excel_files = [
        r"C:\PySC\MSSRV_Mature.xlsx",
        r"C:\PySC\MSWRK_Mature.xlsx",
    ]

    # 1. Gather all descriptions that fall below 90% Pass
    print("Analyzing Excel sheets for low pass rates...")
    failed_descriptions = load_low_pass_descriptions(
        excel_files, threshold=0.90
    )
    print(f"Found {len(failed_descriptions)} items below 90% Pass baseline.")

    # 2. Provide your .audit file content below
    # Replace the triple-quoted string with your actual file data or read it dynamically
    input_audit_data = """
    <custom_item>
      type        : REGISTRY_SETTING
      description : "Ensure 'Configure automatic updates' is set to 'Enabled'"
      value_type  : POLICY_DWORD
      value_data  : 4
    </custom_item>

    <custom_item>
      type        : REGISTRY_SETTING
      description : "Account lockout duration"
      value_type  : POLICY_DWORD
      value_data  : 15
    </custom_item>
    """

    # 3. Process and comment out matching items
    print("\nProcessing audit data...")
    updated_audit_data = comment_audit_content(
        input_audit_data, failed_descriptions
    )

    # 4. Output results
    print("\n--- Processed Audit Output ---")
    print(updated_audit_data)

    # Optional: Save directly to a new file if needed
    # with open("C:\\PySC\\Updated_Policy.audit", "w") as f:
    #     f.write(updated_audit_data)
