"""
This script is a Tenable audit comment-state synchronizer: 
it uses a BASE .audit file as a template and comments matching lines 
in a TARGET .audit file when those lines are commented in the BASE, 
using line position and the first 10 non-space characters as the matching criteria.
"""

import pathlib
import datetime
import shutil

DATE_STR = datetime.datetime.now().strftime("%Y%m%d")

def first_10_non_space(line: str) -> str:
    """
    Return the first 10 non-space characters of a line,
    ignoring leading '#' and whitespace.
    """
    cleaned = line.lstrip().lstrip("#").lstrip()
    return cleaned[:10]

def process_files(base_path: pathlib.Path, target_path: pathlib.Path):
    print(f"\nBase file   : {base_path}")
    print(f"Target file : {target_path}")

    if input("Proceed? [y/N]: ").strip().lower() != "y":
        print("Skipped.")
        return

    backup_path = target_path.with_suffix(target_path.suffix + ".bak")
    output_path = target_path.with_name(
        f"{target_path.stem}_commented_{DATE_STR}{target_path.suffix}"
    )

    # Backup
    shutil.copy2(target_path, backup_path)
    print(f"Backup created: {backup_path}")

    base_lines = base_path.read_text(encoding="utf-8").splitlines(keepends=True)
    target_lines = target_path.read_text(encoding="utf-8").splitlines(keepends=True)

    # Build map: line index -> prefix for commented lines in base file
    base_prefixes = {}
    for i, line in enumerate(base_lines):
        if line.lstrip().startswith("#"):
            base_prefixes[i] = first_10_non_space(line)

    new_lines = []
    for i, line in enumerate(target_lines):
        stripped = line.lstrip()

        # Never touch powershell_args
        if stripped.startswith("powershell_args"):
            new_lines.append(line)
            continue

        if (
            i in base_prefixes
            and not stripped.startswith("#")
            and first_10_non_space(line) == base_prefixes[i]
        ):
            new_lines.append("#" + line)
        else:
            new_lines.append(line)

    output_path.write_text("".join(new_lines), encoding="utf-8")
    print(f"Commented file written: {output_path}")

def main():
    print("Tenable .audit comment synchronizer (10‑char prefix mode)\n")

    while True:
        base = input("Path to BASE .audit file (Enter to quit): ").strip()
        if not base:
            print("Done.")
            break

        target = input("Path to TARGET .audit file: ").strip()

        base_path = pathlib.Path(base)
        target_path = pathlib.Path(target)

        if not base_path.exists() or not target_path.exists():
            print("One or both files not found.")
            continue

        process_files(base_path, target_path)

if __name__ == "__main__":
    main()
