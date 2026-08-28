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
            df = pd.read_excel(path)

            # Standardize column names to lowercase
            df.columns = [str(col).strip().lower() for col in df.columns]

            if "description" not in df.columns or "pass" not in df.columns:
                print(
                    f"Warning: 'Description' or 'Pass' column missing in {path}."
                )
                continue

            # Identify entries failing the 90% threshold
            def is_low_pass(val):
                try:
                    val_float = float(str(val).replace("%", "").strip())
                    if val_float < 1.0:
                        return val_float < threshold
                    return val_float < (threshold * 100)
                except ValueError:
                    return False

            filtered_df = df[df["pass"].apply(is_low_pass)]

            for desc in filtered_df["description"].dropna():
                low_pass_descriptions.add(str(desc).strip())

        except Exception as e:
            print(f"Error processing {path}: {e}")

    return low_pass_descriptions


def comment_low_pass_items(audit_text, low_pass_descriptions):
    """Parses audit text and comments out custom_item blocks matching low-pass descriptions."""
    # Regex to capture individual <custom_item> ... </custom_item> blocks
    block_pattern = re.compile(
        r"(<custom_item>.*?</custom_item>)", re.DOTALL | re.IGNORECASE
    )

    def replace_block(match):
        block = match.group(1)

        # Extract description field inside the block
        desc_match = re.search(
            r"description\s*:\s*[\"'](.*?)[\"']", block, re.IGNORECASE
        )

        if desc_match:
            audit_desc = desc_match.group(1).strip()

            # ONLY comment out if it strictly matches the low pass list
            if audit_desc in low_pass_descriptions:
                commented_block = "\n".join(
                    f"#{line}" for line in block.splitlines()
                )
                print(f"Commenting out item (<90% Pass): {audit_desc}")
                return commented_block

        # Leave the block completely untouched otherwise
        return block

    return block_pattern.sub(replace_block, audit_text)


if __name__ == "__main__":
    excel_files = [
        r"C:\PySC\MSSRV_Mature.xlsx",
        r"C:\PySC\MSWRK_Mature.xlsx",
    ]

    print("Analyzing Excel sheets for low pass rates (< 90%)...")
    failed_descriptions = load_low_pass_descriptions(
        excel_files, threshold=0.90
    )
    print(f"Found {len(failed_descriptions)} items below 90% Pass baseline.")

    # Your raw audit text input from the prompt
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

    print("\nProcessing audit data...")
    updated_audit_data = comment_low_pass_items(
        input_audit_data, failed_descriptions
    )

    print("\n--- Processed Audit Output ---")
    print(updated_audit_data)
