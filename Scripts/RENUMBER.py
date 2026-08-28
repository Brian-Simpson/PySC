from datetime import datetime
import os
import re
import shutil
import tkinter as tk
from tkinter import filedialog


def select_file():
    """Opens a graphical file dialog to select the Tenable audit file."""
    root = tk.Tk()
    root.withdraw()  # Hide the main root window

    file_path = filedialog.askopenfilename(
        title="Select your Tenable Audit file to sequentially re-number",
        filetypes=[
            ("Tenable Audit Files", "*.audit"),
            ("Text Files", "*.txt"),
            ("All Files", "*.*"),
        ],
    )
    return file_path


def main():
    # 1. Prompt user to select the file
    input_file_path = select_file()

    if not input_file_path:
        print("No file selected. Exiting script.")
        return

    # 2. Create the timestamped backup file name (yyyymmddhh)
    timestamp = datetime.now().strftime("%Y%m%d%H")
    directory, full_filename = os.path.split(input_file_path)
    base_name, extension = os.path.splitext(full_filename)

    backup_filename = f"{base_name}_{timestamp}{extension}"
    backup_file_path = os.path.join(directory, backup_filename)

    try:
        shutil.copy2(input_file_path, backup_file_path)
        print(f"Successfully backed up original file to: {backup_file_path}")
    except Exception as e:
        print(f"Failed to create a backup file: {e}")
        return

    # 3. Read the contents of the target file using UTF-8 to prevent encoding issues
    try:
        with open(input_file_path, "r", encoding="utf-8") as file:
            file_content = file.read()
    except UnicodeDecodeError:
        # Fallback to system default encoding if file isn't UTF-8
        with open(input_file_path, "r", encoding="cp1252") as file:
            file_content = file.read()

    # 4. Define tracking counter for re-numbering
    # Scan the file first to find the starting ID dynamically
    start_num_match = re.search(r'(?i)description\s*:\s*["\'](\d+)\.(\d+)', file_content)
    if start_num_match:
        major = int(start_num_match.group(1))
        minor = int(start_num_match.group(2))
    else:
        major = 1
        minor = 382

    # Wrapped in a list so the inner replacer function can modify it across scopes
    counter = [minor]

    # Fixed syntax pattern wrapped in double quotes
    regex_pattern = r"(?i)(description\s*:\s*(['\"]))\d+\.\d+\s*-\s*([^'\"]*)(['\"])"

    def replacer(match):
        prefix = match.group(1)
        quote_type = match.group(2)
        text_summary = match.group(3)

        # Format number dynamically using the extracted major/minor sequence
        padded_number = f"{major}.{counter[0]:04d}"
        counter[0] += 1

        # Reconstruct the matched line dynamically using the correct surrounding quote type
        return f"{prefix}{padded_number} - {text_summary}{quote_type}"

    # 5. Process and replace all descriptions sequentially
    new_content = re.sub(regex_pattern, replacer, file_content)

    # 6. Save the re-serialized dataset directly back into the primary file
    with open(input_file_path, "w", encoding="utf-8") as file:
        file.write(new_content)

    print(
        f"Success! Sequentially updated all custom item identifiers in: {input_file_path}"
    )
    print(f"Total items re-serialized: {counter[0] - minor}")


if __name__ == "__main__":
    main()
