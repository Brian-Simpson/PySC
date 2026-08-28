import pathlib

def lint_file(path: pathlib.Path):
    print(f"\nLinting: {path}\n")

    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()

    for lineno, line in enumerate(lines, start=1):

        # 1. Reject non-ASCII characters (NBSP, smart quotes, etc.)
        if any(ord(c) > 127 for c in line):
            print(f"[ERROR] Line {lineno}: non-ASCII character detected (Tenable parser will fail)")
            continue

        stripped = line.strip()

        # 2. Only inspect powershell_args lines
        if not stripped.startswith("powershell_args"):
            continue

        # 3. Enforce exact Tenable grammar: powershell_args : "
        if not line.startswith('powershell_args : "'):
            print(f"[ERROR] Line {lineno}: powershell_args must start exactly with 'powershell_args : \"' (ASCII spaces only)")
            continue

        # 4. Tabs are illegal near delimiter
        head = line.split("powershell_args", 1)[-1]
        if "\t" in head:
            print(f"[ERROR] Line {lineno}: tab character detected near powershell_args delimiter")
            continue

        # Enforce single-line powershell_args (no continuation)
        if stripped.startswith("powershell_args") and not line.rstrip().endswith('"'):
            print(f"[ERROR] Line {lineno}: powershell_args must be a single physical line (no line breaks)")
            continue

        # 5. Extract value
        try:
            _, value = line.split(":", 1)
            value = value.strip()
        except ValueError:
            print(f"[ERROR] Line {lineno}: malformed powershell_args declaration")
            continue

        # 6. Must start and end with double quote
        if not value.startswith('"') or not value.endswith('"'):
            print(f"[ERROR] Line {lineno}: powershell_args value must be wrapped in double quotes")
            continue

        inner = value[1:-1]

        # 7. Escaped quotes are illegal
        if '\\"' in inner:
            print(f"[ERROR] Line {lineno}: escaped quote (\\\") is NOT supported by Tenable")
            continue

        # 8. Any literal double quote inside breaks Tenable
        if '"' in inner:
            print(f"[ERROR] Line {lineno}: unescaped double quote inside powershell_args")
            continue

    print("\nLint complete.\n")


def main():
    print("Tenable.io PowerShell audit parser compatibility checker\n")

    while True:
        p = input("Path to .audit file (Enter to quit): ").strip()
        if not p:
            break

        path = pathlib.Path(p)
        if not path.exists():
            print("File not found.\n")
            continue

        lint_file(path)


if __name__ == "__main__":
    main()