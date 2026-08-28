"""
This script is a safe commenting utility for Tenable .audit files. 
It creates a backup of an audit file and writes a new version where almost every active line has been commented out with #.

"""

import pathlib
import datetime
import shutil

DATE_STR = datetime.datetime.now().strftime("%Y%m%d")

def should_comment_line(line: str) -> bool:
    stripped = line.lstrip()
    return (
        stripped != "" and
        not stripped.startswith("#") and
        not stripped.startswith("powershell_args")
    )

def process_file(file_path: pathlib.Path):
    print(f"\nProcessing file: {file_path}")

    confirm = input("Proceed with this file? [y/N]: ").strip().lower()
    if confirm != "y":
        print("Skipped.")
        return

    backup_path = file_path.with_suffix(file_path.suffix + ".bak")
    output_path = file_path.with_name(
        f"{file_path.stem}_commented_{DATE_STR}{file_path.suffix}"
    )

    # Create backup
    shutil.copy2(file_path, backup_path)
    print(f"Backup created: {backup_path}")

    with file_path.open("r", encoding="utf-8") as f:
        lines = f.readlines()

    new_lines = []
    for line in lines:
        if should_comment_line(line):
            new_lines.append("#" + line)
        else:
            new_lines.append(line)

    with output_path.open("w", encoding="utf-8") as f:
        f.writelines(new_lines)

    print(f"Commented file written: {output_path}")

def main():
    print("Tenable .audit commenter (safe mode)")
    print("Enter file paths one at a time. Press Enter to quit.\n")

    while True:
        path_input = input("Path to .audit file: ").strip()
        if not path_input:
            print("Done.")
            break

        file_path = pathlib.Path(path_input)
        if not file_path.exists():
            print("File not found.")
            continue

        process_file(file_path)

if __name__ == "__main__":
    main()
    