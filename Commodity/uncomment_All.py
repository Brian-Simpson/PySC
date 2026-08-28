#!/usr/bin/env python3
"""Uncomment all lines in .audit files, including <custom_item> blocks. in a .audit file.

This is a helper script for debugging and testing, to quickly uncomment all lines in a .audit file.

"""


from __future__ import annotations

import argparse
from pathlib import Path
import re


OPEN_PATTERN = re.compile(r"^(?P<indent>\s*)#\s*<custom_item>\s*$")
CLOSE_PATTERN = re.compile(r"^(?P<indent>\s*)#\s*</custom_item>\s*$")
COMMENT_LINE_PATTERN = re.compile(r"^(?P<indent>\s*)#\s*(?P<body>.*)$")


def detect_newline(text: str) -> str:
    if "\r\n" in text:
        return "\r\n"
    if "\r" in text:
        return "\r"
    return "\n"

def output_path_for_input(input_path: Path) -> Path:
    if input_path.suffix != ".audit":
        return input_path.with_name(f"{input_path.stem}.uncommented{input_path.suffix}")
    return input_path.with_name(f"{input_path.name}_uncommented.audit")

def uncomment_custom_item_blocks(text: str) -> tuple[str, int]:
    newline = detect_newline(text)
    lines = text.split(newline)

    out_lines: list[str] = []
    in_commented_block = False
    blocks_uncommented = 0

    for line in lines:
        open_match = OPEN_PATTERN.match(line)
        if open_match:
            in_commented_block = True
            blocks_uncommented += 1
            out_lines.append(open_match.group("indent") + "<custom_item>")
            continue

        if in_commented_block:
            close_match = CLOSE_PATTERN.match(line)
            if close_match:
                in_commented_block = False
                out_lines.append(close_match.group("indent") + "</custom_item>")
                continue

            comment_match = COMMENT_LINE_PATTERN.match(line)
            if comment_match:
                out_lines.append(f"{comment_match.group('indent')}{comment_match.group('body')}")
            else:
                out_lines.append(line)
            continue

        out_lines.append(line)

    return newline.join(out_lines), blocks_uncommented

def resolve_input_path(args: argparse.Namespace) -> Path:
    if args.path:
        return Path(args.path).expanduser()
    
    value = input("Enter the path to the .audit file to uncomment: ").strip('"')
    if not value:
        raise SystemExit("No path provided. Exiting.")
    return Path(value).expanduser()

def main() -> None:
    parser = argparse.ArgumentParser(description="Uncomment all lines in a .audit file, including <custom_item> blocks.")
    parser.add_argument("path", nargs="?", help="Path to the .audit file to uncomment")
    args = parser.parse_args()

    input_path = resolve_input_path(args)
    if not input_path.exists() or not input_path.is_file():
        raise SystemExit(f"File not found: {input_path}")

    original = input_path.read_text(encoding="ascii", errors="ignore")
    transformed, count = uncomment_custom_item_blocks(original)

    output_path = output_path_for_input(input_path)
    with output_path.open("w", encoding="ascii", newline="") as f:
        f.write(transformed)

    print(f"Blocks uncommented: {count}. Output written to: {output_path}")
    print(f"Wrote: {output_path}")

if __name__ == "__main__":
    main()
