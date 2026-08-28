#!/usr/bin/env python3
"""Align, validate, and optionally fix custom_item numbering in .audit files.

Usage examples:
  python C:\\PySC\\CheckAuditSequence.py C:\\PySC\\HTH_Win_11_Enterprise.audit
  python C:\\PySC\\CheckAuditSequence.py C:\\PySC\\HTH_Win_11_Enterprise.audit --fix
  python C:\\PySC\\CheckAuditSequence.py C:\\PySC\\IOS_New20260507_All in_1.audit --align --fix --dry-run
  & "C:\\Users\\brian.simpson\\OneDrive - Hilltop Holdings\\PySC\\venv\\Scripts\\python.exe" "C:\\PySC\\CheckAuditSequence.py" "C:\\PySC\\Normalization\\Azure\\CIS_Microsoft_Azure_Foundations_v5.0.0_L1-normalized1.audit" --align --fix --audit-type Azure
  python C:\\PySC\\CheckAuditSequence.py C:\\PySC\\Normalization\\IOS\\IOS_New20260515_All.audit --fix

  python C:\\PySC\\CheckAuditSequence.py C:\\PySC\\HTH_MSSRV_192225_20260514_01.audit --align --fix
"""

from __future__ import annotations

import argparse
import re
import shutil
from pathlib import Path


BLOCK_START_PATTERN = re.compile(r"^\s*(#\s*)?(<custom_item>|<item>)\s*$")
BLOCK_END_PATTERN = re.compile(r"^\s*(#\s*)?(</custom_item>|</item>)\s*$")
DESCRIPTION_PATTERN = re.compile(r'^\s*(#\s*)?description\s*:\s*"(?P<text>.*)"\s*$')
NUMBER_PATTERN = re.compile(r"^(?P<number>\d+(?:\.\d+)+)\b")

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
		match = KEY_PATTERN.match(line)
		if not match:
			continue
		trimmed = line.lstrip()
		if trimmed.startswith("<"):
			continue
		max_len = max(max_len, len(match.group(2)))
	return max_len


def align_pass_one(lines: list[str], max_key_len: int) -> list[str]:
	"""Align tag indentation by nesting and normalize key/value colon alignment."""
	out: list[str] = []
	tag_level = 0

	for line in lines:
		trimmed = line.lstrip()

		commented_match = COMMENTED_TAG_PATTERN.match(trimmed)
		if commented_match:
			tag_text = commented_match.group(1)
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

		key_match = KEY_PATTERN.match(line)
		if key_match:
			prefix, key, value = key_match.groups()
			out.append(f"{prefix}{key.ljust(max_key_len)} : {value}")
			continue

		out.append(line)

	return out


def align_pass_two(lines: list[str], max_key_len: int) -> list[str]:
	"""Enforce consistent key/value indentation inside active and commented blocks."""
	out: list[str] = []
	in_comment = False
	active_indents: list[str] = []
	comment_prefix = ""

	for line in lines:
		trimmed = line.lstrip()

		if not trimmed.startswith("#") and OPEN_TAG_PATTERN.match(trimmed) and not trimmed.startswith("</"):
			active_indents.append(re.match(r"^(\s*)", line).group(1))
			out.append(line)
			continue

		if not trimmed.startswith("#") and TAG_PATTERN.match(trimmed) and trimmed.startswith("</"):
			if active_indents:
				active_indents.pop()
			out.append(line)
			continue

		if re.match(r"^#\s*<custom_item>\s*$", trimmed):
			in_comment = True
			comment_prefix = re.match(r"^(\s*)", line).group(1) + "# "
			out.append(line)
			continue

		if re.match(r"^#\s*</custom_item>\s*$", trimmed):
			in_comment = False
			comment_prefix = ""
			out.append(line)
			continue

		if active_indents:
			active_match = KV_ACTIVE.match(line)
			if active_match:
				key, value = active_match.groups()
				out.append(f"{active_indents[-1]}  {key.ljust(max_key_len)} : {value}")
				continue

		if in_comment:
			comment_match = KV_COMMENT.match(line)
			if comment_match:
				key, value = comment_match.groups()
				out.append(f"{comment_prefix}{key.ljust(max_key_len)} : {value}")
				continue

		out.append(line)

	return out


def align_file(path: Path, dry_run: bool) -> bool:
	original = path.read_text(encoding="ascii", errors="ignore")
	newline = detect_newline(original)
	lines = original.splitlines()

	max_key_len = compute_max_key_len(lines)
	stage1 = align_pass_one(lines, max_key_len)
	stage2 = align_pass_two(stage1, max_key_len)
	aligned = newline.join(stage2) + newline

	if aligned == original:
		print("Alignment: no changes needed.")
		return False

	if dry_run:
		print(f"Dry run: alignment changes would be applied to {path}")
		return True
	with path.open("w", encoding="ascii", newline="") as f:
		f.write(aligned)
	print(f"Alignment: applied changes to {path}")
	return True


def parse_audit(path: Path) -> list[dict[str, object]]:
	entries: list[dict[str, object]] = []
	lines = path.read_text(encoding="ascii", errors="ignore").splitlines()
	last_then = 0
	for index, line in enumerate(lines, start=1):
		if line.strip() == "</then>":
			last_then = index

	for line_number, line in enumerate(lines, start=1):
		if last_then and line_number > last_then:
			break

		match = DESCRIPTION_PATTERN.match(line)
		if not match:
			continue

		description = match.group("text")
		number_match = NUMBER_PATTERN.match(description)
		if not number_match:
			continue

		number_str = number_match.group("number")
		number_parts = [int(x) for x in number_str.split(".")]
		section = number_parts[0]
		item = number_parts[1] if len(number_parts) > 1 else 0
		entries.append(
			{
				"section": section,
				"item": item,
				"number": number_str,
				"number_parts": number_parts,
				"description": description,
				"line": line_number,
				"line_text": line,
			}
		)

	return entries


def compute_expected_entries(entries: list[dict[str, object]]) -> list[dict[str, object]]:
	expected_entries: list[dict[str, object]] = []
	counter = 0

	for entry in entries:
		counter += 1
		expected_number = f"1.{counter:04d}"
		expected_entries.append(
			{
				**entry,
				"expected_number": expected_number,
			}
		)

	return expected_entries


def find_sequence_issues(entries: list[dict[str, object]]) -> list[str]:
	issues: list[str] = []

	if not entries:
		issues.append("No numbered custom_item descriptions were found.")
		return issues

	for previous, current in zip(entries, entries[1:]):
		prev_parts = previous.get("number_parts", [int(previous["section"]), int(previous["item"])])
		curr_parts = current.get("number_parts", [int(current["section"]), int(current["item"])])

		if tuple(curr_parts) == tuple(prev_parts):
			issues.append(
				f"Duplicate number {current['number']} at line {current['line']} (previous at line {previous['line']})."
			)
			continue

		if tuple(curr_parts) < tuple(prev_parts):
			issues.append(
				f"Out-of-order number: {current['number']} at line {current['line']} follows {previous['number']} at line {previous['line']}."
			)
			continue

		# Check for gaps in sequential numbering
		if len(prev_parts) == len(curr_parts) == 2:
			prev_section, prev_item = prev_parts
			curr_section, curr_item = curr_parts
			if curr_section == prev_section and curr_item > prev_item + 1:
				missing = ", ".join(f"{prev_section}.{value:04d}" for value in range(prev_item + 1, curr_item))
				issues.append(
					f"Gap after {previous['number']} at line {previous['line']}: skipped {missing} before {current['number']} at line {current['line']}."
				)
				continue

	return issues


def validate_entries(entries: list[dict[str, object]], path: Path) -> int:
	issues = find_sequence_issues(entries)

	print(f"Scanned {len(entries)} numbered custom_item blocks in {path}")

	if issues:
		print("Sequence check failed:")
		for issue in issues:
			print(f"- {issue}")
		return 1

	first = entries[0]["number"]
	last = entries[-1]["number"]
	print(f"Sequence check passed: {first} through {last} with no skips.")
	return 0


def rewrite_descriptions(path: Path, entries: list[dict[str, object]], audit_type: str, dry_run: bool) -> bool:
	expected_entries = compute_expected_entries(entries)
	updates: list[dict[str, object]] = []
	for entry in expected_entries:
		line_text = entry.get("line_text", "")
		has_audit = bool(
			re.search(
				rf'^\s*description\s*:\s*"{re.escape(entry["number"])}\s*-\s*{re.escape(audit_type)}\s*-',
				line_text,
			)
		)
		if entry["number"] != entry["expected_number"] or not has_audit:
			updates.append(entry)

	if not updates:
		print("No renumbering or audit-type insertion needed.")
		return False

	if dry_run:
		print(f"Dry run: {len(updates)} renumber changes would be applied to {path}")
		for entry in updates[:20]:
			print(f"- line {entry['line']}: {entry['number']} -> {entry['expected_number']}")
		remaining = len(updates) - 20
		if remaining > 0:
			print(f"- ... and {remaining} more")
		return True

	original = path.read_text(encoding="ascii", errors="ignore")
	newline = detect_newline(original)
	lines = original.splitlines()

	for entry in reversed(updates):
		line_index = int(entry["line"]) - 1
		old_number = re.escape(str(entry["number"]))
		new_number = str(entry["expected_number"])
		line = lines[line_index]
		def replace_line(m: re.Match[str], value: str = new_number, audit: str = audit_type) -> str:
			after = m.group("after")
			existing_audit_match = re.match(r'^\s*-\s*(.+?)\s*-\s*(.*)$', after)
			if existing_audit_match:
				rest = existing_audit_match.group(2)
				if rest.startswith(" "):
					rest = rest[1:]
				return m.group("prefix") + value + f" - {audit} - " + rest
			return m.group("prefix") + value + f" - {audit} - " + after
		line = re.sub(
			rf'^(?P<prefix>\s*description\s*:\s*")' + old_number + r'(?P<after>.*)$',
			replace_line,
			line,
			count=1,
		)
		lines[line_index] = line
	output = newline.join(lines) + newline
	with path.open("w", encoding="ascii", newline="") as f:
		f.write(output)
	print(f"Renumbered {len(updates)} custom_item descriptions in {path}")

	for entry in updates[:10]:
		print(f"- line {entry['line']}: {entry['number']} -> {entry['expected_number']}")

	remaining = len(updates) - 10
	if remaining > 0:
		print(f"- ... and {remaining} more")

	return True


def build_parser() -> argparse.ArgumentParser:
	parser = argparse.ArgumentParser(description="Align, validate, or fix custom_item numbering in .audit files.")
	parser.add_argument("path", nargs="?", help="Path to the .audit file")
	parser.add_argument("--align", action="store_true", help="Run alignment formatter before sequence operations")
	parser.add_argument("--fix", action="store_true", help="Renumber custom_item descriptions to remove gaps")
	parser.add_argument("--audit-type", help="Audit type label to insert after the number, e.g. Azure")
	parser.add_argument("--dry-run", action="store_true", help="Preview changes without modifying the file")
	parser.add_argument("--no-backup", action="store_true", help="Do not create a .bak backup when applying writes")
	return parser


def resolve_target(args: argparse.Namespace) -> Path:
	if args.path:
		return Path(args.path).expanduser()

	file_input = input("Enter full path to .audit file: ").strip().strip('"')
	if not file_input:
		print("No file path provided.")
		raise SystemExit(1)

	return Path(file_input).expanduser()


def maybe_backup(path: Path, dry_run: bool, no_backup: bool, will_write: bool) -> None:
	if dry_run or no_backup or not will_write:
		return
	backup_path = path.with_suffix(path.suffix + ".bak")
	shutil.copyfile(path, backup_path)
	print(f"Backup created: {backup_path}")


def main() -> None:
	parser = build_parser()
	args = parser.parse_args()
	target = resolve_target(args)
	if not target.exists() or not target.is_file():
		print(f"File not found: {target}")
		raise SystemExit(1)

	audit_type = args.audit_type
	if args.fix and not audit_type:
		audit_type = input("Enter audit type label: ").strip()
		if not audit_type:
			print("No audit type provided.")
			raise SystemExit(1)

	will_write = args.align or args.fix
	maybe_backup(target, dry_run=args.dry_run, no_backup=args.no_backup, will_write=will_write)

	if args.align:
		align_file(target, dry_run=args.dry_run)

	entries = parse_audit(target)
	if args.fix:
		rewrite_descriptions(target, entries, audit_type, dry_run=args.dry_run)
		if not args.dry_run:
			entries = parse_audit(target)

	raise SystemExit(validate_entries(entries, target))


if __name__ == "__main__":
	main()