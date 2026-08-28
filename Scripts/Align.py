#!/usr/bin/env python3
"""Format .audit files by aligning key/value pairs and tag indentation.

Rules implemented:
1) Align key/value rows so ':' is in one vertical column.
2) Re-indent XML-like tag lines by nesting depth.
3) Enforce a consistent left indent for key/value rows inside each
   <custom_item>...</custom_item> block (and commented # <custom_item> blocks).
"""

from __future__ import annotations

from pathlib import Path
import re


KEY_PATTERN = re.compile(r"^(\s*#?\s*)([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$")
TAG_PATTERN = re.compile(r"^</?[A-Za-z_][^>]*>$")
OPEN_TAG_PATTERN = re.compile(r"^<[^/!][^>]*>$")
COMMENTED_TAG_PATTERN = re.compile(r"^#\s*(</?[A-Za-z_][^>]*>)\s*$")

KV_ACTIVE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$")
KV_COMMENT = re.compile(r"^\s*#\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$")


def detect_newline(text: str) -> str:
	if "\r\n" in text:
		return "\r\n"
	if "\r" in text:
		return "\r"
	return "\n"


def compute_max_key_len(lines: list[str]) -> int:
	max_len = 0
	for line in lines:
		m = KEY_PATTERN.match(line)
		if not m:
			continue
		trimmed = line.lstrip()
		if trimmed.startswith("<"):
			continue
		key = m.group(2)
		max_len = max(max_len, len(key))
	return max_len


def pass_one(lines: list[str], max_key_len: int) -> list[str]:
	"""Align tags by nesting and normalize key:value colon alignment."""
	out: list[str] = []
	tag_level = 0

	for line in lines:
		trimmed = line.lstrip()

		cm = COMMENTED_TAG_PATTERN.match(trimmed)
		if cm:
			tag_text = cm.group(1)
			if tag_text.startswith("</"):
				tag_level = max(0, tag_level - 1)
			out.append(("  " * tag_level) + "# " + tag_text)
			if OPEN_TAG_PATTERN.match(tag_text) and not tag_text.endswith("/>"):
				tag_level += 1
			continue

		if not trimmed.startswith("#") and TAG_PATTERN.match(trimmed):
			if trimmed.startswith("</"):
				tag_level = max(0, tag_level - 1)

			out.append(("  " * tag_level) + trimmed)

			if OPEN_TAG_PATTERN.match(trimmed) and not trimmed.endswith("/>"):
				tag_level += 1
			continue

		m = KEY_PATTERN.match(line)
		if m:
			prefix, key, value = m.groups()
			out.append(f"{prefix}{key.ljust(max_key_len)} : {value}")
			continue

		out.append(line)

	return out


def pass_two(lines: list[str], max_key_len: int) -> list[str]:
	"""Enforce one consistent left indent for key:value lines in active blocks."""
	out: list[str] = []
	in_comment = False
	active_indents: list[str] = []
	comment_prefix = ""

	for line in lines:
		trimmed = line.lstrip()

		if not trimmed.startswith("#") and OPEN_TAG_PATTERN.match(trimmed) and not trimmed.startswith("</"):
			active_indents.append(re.match(r"^(\s*).*", line).group(1))
			out.append(line)
			continue

		if not trimmed.startswith("#") and TAG_PATTERN.match(trimmed) and trimmed.startswith("</"):
			if active_indents:
				active_indents.pop()
			out.append(line)
			continue

		if re.match(r"^#\s*<custom_item>\s*$", trimmed):
			in_comment = True
			leading = re.match(r"^(\s*)", line).group(1)
			comment_prefix = leading + "# "
			out.append(line)
			continue

		if re.match(r"^#\s*</custom_item>\s*$", trimmed):
			in_comment = False
			comment_prefix = ""
			out.append(line)
			continue

		if active_indents:
			m = KV_ACTIVE.match(line)
			if m:
				key, value = m.groups()
				out.append(f"{active_indents[-1]}  {key.ljust(max_key_len)} : {value}")
				continue

		if in_comment:
			m = KV_COMMENT.match(line)
			if m:
				key, value = m.groups()
				out.append(f"{comment_prefix}{key.ljust(max_key_len)} : {value}")
				continue

		out.append(line)

	return out


def format_file(path: Path) -> None:
	original = path.read_text(encoding="ascii", errors="ignore")
	newline = detect_newline(original)
	lines = original.splitlines()

	max_key_len = compute_max_key_len(lines)
	stage1 = pass_one(lines, max_key_len)
	stage2 = pass_two(stage1, max_key_len)
	output = newline.join(stage2) + newline
	with path.open("w", encoding="ascii", newline="") as f:
		f.write(output)


def main() -> None:
	file_input = input("Enter full path to .audit file: ").strip().strip('"')
	if not file_input:
		print("No file path provided.")
		raise SystemExit(1)

	target = Path(file_input)
	if not target.exists() or not target.is_file():
		print(f"File not found: {target}")
		raise SystemExit(1)

	format_file(target)
	print(f"Formatted: {target}")


if __name__ == "__main__":
	main()
