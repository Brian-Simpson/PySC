#!/usr/bin/env python3
"""
normalize_f5_audit.py
1. Extracts variable definitions (e.g., REQUIRED_SPECIAL) from audit comments.
2. Populates all @VARIABLE@ references throughout the file using their default values.
3. Performs standard structural tag normalization for Tenable.io compliance.
"""

import re
import subprocess
import sys
import argparse
from datetime import datetime
from pathlib import Path

DEFAULT_DIR = r"C:\PySC\Audits\f5" \
""

def clean_file_encoding(raw_bytes: bytes) -> str:
    """Strip BOM and decode file content safely to standard ASCII/UTF-8."""
    if raw_bytes.startswith(b'\xef\xbb\xbf'):
        raw_bytes = raw_bytes[3:]
    
    for encoding in ['utf-8', 'latin-1', 'cp1252', 'ascii']:
        try:
            return raw_bytes.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw_bytes.decode('utf-8', errors='ignore')

def substitute_audit_variables(text: str) -> str:
    """
    Finds variable declarations in commented blocks and replaces their placeholders.
    Example: Extracts <name>REQUIRED_SPECIAL</name> and <default>[^0]+</default>
    Then replaces all instances of @REQUIRED_SPECIAL@ with [^0]+.
    """
    # Regex to find individual <variable>...</variable> structures within lines starting with #
    # Uses re.DOTALL to capture multi-line structures cleanly
    variable_block_regex = re.compile(r'#\s*<variable>(.*?)#\s*</variable>', re.DOTALL | re.IGNORECASE)
    
    name_regex = re.compile(r'<name>\s*(.*?)\s*</name>', re.IGNORECASE)
    default_regex = re.compile(r'<default>\s*(.*?)\s*</default>', re.IGNORECASE)
    value_regex = re.compile(r'<value>\s*(.*?)\s*</value>', re.IGNORECASE) # Backup if <value> is used instead of <default>

    variables = {}

    # Extract all variable blocks
    for block_match in variable_block_regex.finditer(text):
        block_content = block_match.group(1)
        
        name_m = name_regex.search(block_content)
        if not name_m:
            continue
            
        var_name = name_m.group(1).strip()
        
        # Determine value prioritizing <default>, then <value>
        var_value = ""
        default_m = default_regex.search(block_content)
        if default_m:
            var_value = default_m.group(1).strip()
        else:
            value_m = value_regex.search(block_content)
            if value_m:
                var_value = value_m.group(1).strip()
        
        if var_name:
            variables[var_name] = var_value

    # Substitute placeholders globally across the file
    if variables:
        print(f"   [i] Extracted {len(variables)} policy variables to populate.")
        for var_name, var_value in variables.items():
            placeholder = f"@{var_name}@"
            if placeholder in text:
                text = text.replace(placeholder, var_value)
                
    return text

# Only these are treated as key-value keys inside <item> blocks.
# Any other "word:" line is treated as continuation content, not a new key.
ALLOWED_KEYS = {
    "description",
    "info",
    "solution",
    "reference",
    "see_also",
    "context",
    "regex",
    "expect",
    "f5_command",
    "json_transform",
    "show_output",
    "not_expect",
    "item",
    "content",
}

SUMMARY_KEYS = {"description", "info", "solution"}
MAX_SUMMARY_SENTENCES = 3
IGNORED_LINES = re.compile(r"^\s*(?:tmsh|impact)\s*:\s*$", re.IGNORECASE)
KEY_LINE = re.compile(r"^([a-zA-Z0-9_-]+)\s*:\s*(.*)$")
DOCKER_IMAGE = "tenable/audit-utils:latest"

def compact_summary_value(value: str) -> str:
    """Flatten a report summary and retain no more than three sentences."""
    value = re.sub(r"\s+", " ", value).strip()
    quoted = value.startswith('"')
    if quoted:
        value = value[1:]
    if value.endswith('"'):
        value = value[:-1].rstrip()

    sentences = re.split(r"(?<=[.!?])\s+", value)
    value = " ".join(sentences[:MAX_SUMMARY_SENTENCES]).strip()
    value = value.replace('\\"', "").replace('"', "")
    return f'"{value}"' if quoted else value

def compact_summary_lines(lines: list[str]) -> list[str]:
    """Collapse continuation lines for report description, info, and solution."""
    compacted = []
    index = 0
    while index < len(lines):
        line = lines[index]
        match = KEY_LINE.match(line.strip())
        if IGNORED_LINES.match(line):
            index += 1
            while index < len(lines):
                continuation = lines[index].strip()
                continuation_key = KEY_LINE.match(continuation)
                if continuation_key or continuation.startswith("<") or continuation.startswith("</"):
                    break
                index += 1
            continue

        if not match or match.group(1).lower() not in SUMMARY_KEYS:
            compacted.append(line)
            index += 1
            continue

        key, value = match.group(1), match.group(2)
        parts = [value]
        index += 1
        while index < len(lines):
            continuation = lines[index].strip()
            continuation_key = KEY_LINE.match(continuation)
            if (
                (continuation_key and continuation_key.group(1).lower() in ALLOWED_KEYS)
                or continuation.startswith("<")
                or continuation.startswith("</")
            ):
                break
            if continuation:
                parts.append(continuation)
            index += 1

        indent = line[:len(line) - len(line.lstrip())]
        compacted.append(f"{indent}{key} : {compact_summary_value(' '.join(parts))}")

    return compacted

def normalize_reference_value(value: str) -> str:
    """Keep only NIST 800-53 revision 5 controls in compact form."""
    value = value.strip()
    if value.startswith('"'):
        value = value[1:]
    if value.endswith('"'):
        value = value[:-1]

    controls = re.findall(r"800-53r5\|([^,\s\"]+)", value, re.IGNORECASE)
    if not controls:
        return '""'
    return f'"NIST 800-53r5|{" ".join(controls)}"'

def indent_structured_lines(content: str) -> str:
    """Indent tags and keys according to their surrounding audit blocks."""
    output = []
    stack = []
    tag_pattern = re.compile(r"^</?\s*([a-zA-Z0-9_-]+)")

    for line in content.split("\n"):
        stripped = line.strip()
        if not stripped:
            output.append("")
            continue

        tag_match = tag_pattern.match(stripped)
        if tag_match and stripped.startswith("</"):
            if stack:
                stack.pop()
            indent = "\t" * len(stack)
            output.append(f"{indent}{stripped}")
        elif tag_match and stripped.startswith("<"):
            indent = "\t" * len(stack)
            output.append(f"{indent}{stripped}")
            if (
                tag_match.group(1).lower() != "check_type"
                and not stripped.startswith("<!")
                and not stripped.endswith("/>")
            ):
                stack.append(tag_match.group(1).lower())
        else:
            indent = "\t" * len(stack)
            output.append(f"{indent}{stripped}")

    return "\n".join(output)

def normalize_tags(text: str) -> str:
    """Flatten conditional audit logic into independent custom_item checks."""
    text = text.replace('\r\n', '\n').replace('\r', '\n')
    block_regex = re.compile(
        r"(?ms)<(?:custom_item|item)\b[^>]*>(.*?)</(?:custom_item|item)\s*>",
        re.IGNORECASE,
    )
    report_regex = re.compile(r"(?ms)<report\b[^>]*>(.*?)</report\s*>", re.IGNORECASE)
    controls = []
    previous_fields = {}
    required_keys = ("description", "info", "reference", "see_also", "solution")
    for match in block_regex.finditer(text):
        parsed_fields = {}
        preceding_reports = list(report_regex.finditer(text, 0, match.start()))
        if preceding_reports:
            for line in preceding_reports[-1].group(1).splitlines():
                field = KEY_LINE.match(line.strip())
                if field and field.group(1).lower() in required_keys:
                    parsed_fields[field.group(1).lower()] = field.group(2).strip()
        for line in match.group(1).splitlines():
            field = KEY_LINE.match(line.strip())
            if not field or field.group(1).lower() not in ALLOWED_KEYS:
                continue
            key, val = field.group(1).lower(), field.group(2).strip()
            parsed_fields[key] = val

        if "context" in parsed_fields and (
            "f5_command" not in parsed_fields or "json_transform" not in parsed_fields
        ):
            continue

        fields = []
        for key in required_keys:
            if key not in parsed_fields:
                parsed_fields[key] = previous_fields.get(key, '""')
        ordered_keys = list(required_keys) + [
            key for key in parsed_fields if key not in required_keys
        ]
        for key in ordered_keys:
            val = parsed_fields[key]
            if key == "reference":
                val = normalize_reference_value(val)
            elif key == "see_also":
                val = '"See HTH Policies and Standards"'
            elif key in SUMMARY_KEYS:
                clean_val = val.strip('"').replace('\\"', '').replace('"', '')
                val = f'"{clean_val}"'
            elif not (val.startswith('"') and val.endswith('"')) and not val.isdigit():
                val = f'"{val.replace(chr(34), chr(92) + chr(34))}"'
            fields.append((key, val))
        if fields:
            controls.append(fields)
            previous_fields.update(parsed_fields)

    key_width = max((len(key) for fields in controls for key, _ in fields), default=0)
    output = ['<check_type:"F5">', ""]
    for fields in controls:
        output.append("<custom_item>")
        output.extend(f"{key:<{key_width}} : {value}" for key, value in fields)
        output.extend(["</custom_item>", ""])
    output.append("</check_type>")
    return "\n".join(output)

def verify_with_docker(file_path: Path) -> None:
    """Validate an audit file using Tenable's audit-utils Docker image."""
    file_path = file_path.resolve()
    directory = file_path.parent
    container_file = f"/audits/{file_path.name}"
    command = [
        "docker", "run", "--rm",
        "-v", f"{directory}:/audits",
        DOCKER_IMAGE, "check_service", container_file,
    ]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except FileNotFoundError as error:
        raise RuntimeError("Docker is required to verify normalized audit files.") from error
    except subprocess.TimeoutExpired as error:
        output = f"{error.stdout or ''}\n{error.stderr or ''}"
        if "Starting HTTP server" not in output:
            raise RuntimeError(f"Docker audit validation timed out for {file_path.name}.") from error
        return

    output = f"{result.stdout}\n{result.stderr}"
    if result.returncode != 0 or "error" in output.lower():
        raise RuntimeError(
            f"Docker audit validation failed for {file_path.name}:\n{output.strip()}"
        )

def process_single_file(file_path: Path):
    """Normalizes a single specific file path object."""
    if "baseline" in file_path.name.lower():
        print(f"[-] Skipping baseline file: '{file_path.name}'")
        return

    timestamp = datetime.now().strftime("%y%m%d%H%M")
    output_path = file_path.with_name(
        f"{file_path.stem}_normalized_{timestamp}{file_path.suffix}"
    )
    print(f"[*] Processing: '{file_path.name}' -> '{output_path.name}'")
    
    try:
        raw_data = file_path.read_bytes()
        decoded_text = clean_file_encoding(raw_data)
        
        # Step 1: Inline variable substitutions
        hydrated_text = substitute_audit_variables(decoded_text)
        
        # Step 2: Format structure and elements
        processed_text = normalize_tags(hydrated_text)
        
        output_path.write_text(processed_text, encoding='utf-8')
        verify_with_docker(output_path)
        print(f"[+] Docker parse validation passed: '{output_path.name}'")
    except Exception as e:
        print(f"[-] Error processing {file_path.name}: {e}", file=sys.stderr)
        raise

def process_directory(dir_path: Path):
    """Scans a folder and processes all source audit files inside it."""
    audit_files = list(dir_path.glob("*.audit")) + list(dir_path.glob("*.AUDIT"))
    audit_files = sorted(list(set([f for f in audit_files if "_normalized" not in f.name])))

    if not audit_files:
        print(f"[-] No source '.audit' files found in folder: '{dir_path}'")
        return

    print(f"\n[+] Found {len(audit_files)} file(s) in '{dir_path}'. Starting normalization...\n" + "="*60)
    for target_file in audit_files:
        process_single_file(target_file)
    print("="*60 + "\n[+] Folder processing complete!")

def main():
    parser = argparse.ArgumentParser(description="Normalize F5 BIG-IP .audit files for Tenable.io compliance.")
    parser.add_argument("-i", "--input", help="Path to raw F5 .audit file or folder", default=None)
    
    args = parser.parse_args()
    input_val = args.input

    if not input_val:
        prompt_msg = f"Enter path or press [Enter] to batch process ALL .audit files in '{DEFAULT_DIR}': "
        user_input = input(prompt_msg).strip()
        user_input = user_input.strip("'").strip('"').strip()
        input_val = user_input if user_input else "BATCH_DEFAULT"

    # 1. Default batch behavior if nothing was entered
    if input_val == "BATCH_DEFAULT":
        dir_path = Path(DEFAULT_DIR)
        if dir_path.is_dir():
            process_directory(dir_path)
        else:
            print(f"[-] Error: Default directory '{DEFAULT_DIR}' does not exist.", file=sys.stderr)
            sys.exit(1)

    # 2. Strict matching for exact string input
    else:
        input_p = Path(input_val)
        
        if input_p.is_dir():
            process_directory(input_p)
        elif input_p.is_file():
            print("\n" + "="*60)
            process_single_file(input_p)
            print("="*60 + "\n[+] File processing complete!")
        else:
            print(f"\n[-] Error: '{input_val}' is not a valid file or directory path.", file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    main()
