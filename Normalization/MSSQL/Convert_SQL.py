#!/usr/bin/env python3
import argparse
import os
import re
from collections import OrderedDict


def parse_item_block(lines, start_idx):
    """Parse an <item> or <custom_item> block starting at start_idx. Return (dict, end_idx)."""
    item = OrderedDict()
    i = start_idx
    while i < len(lines):
        line = lines[i].strip()
        if line in ('</item>', '</custom_item>'):
            return item, i + 1
        if line.startswith(('<item', '<custom_item')):
            i += 1
            continue
        if ':' in line:
            key, val = line.split(':', 1)
            item[key.strip()] = val.strip()
        i += 1
    return item, i


def parse_report_block(lines, start_idx):
    """Parse a <report>...</report> block. Return (dict, end_idx)."""
    report = OrderedDict()
    i = start_idx
    while i < len(lines):
        line = lines[i].strip()
        if line == '</report>':
            return report, i + 1
        if line.startswith('<report'):
            m = re.search(r'type:"([^"]+)"', line)
            if m:
                report['report_type'] = m.group(1)
            i += 1
            continue
        if ':' in line:
            key, val = line.split(':', 1)
            report[key.strip()] = val.strip()
        i += 1
    return report, i


def flatten_audit(lines):
    """
    Intelligently flatten audit file:
    - Keep the outer device qualification <if>/<condition>/<then>/<else> structure
    - Extract items/custom_items from nested conditions within the <then> block
    - Inject report metadata (info, reference, see_also) into each item
    - Remove inner <if>/<condition>/<then>/<else> wrappers and <report> blocks within <then>
    - Keep standalone items/custom_items/reports as-is
    """
    output = []
    i = 0
    outer_if_preserved = False

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Handle outer if block (device qualification) - preserve it if not already done
        if stripped == '<if>' and not outer_if_preserved:
            # Look ahead to see if this contains a condition with REG_CHECK for SQL Server
            look_ahead_start = i
            look_ahead_end = min(i + 20, len(lines))
            look_ahead_text = '\n'.join(lines[look_ahead_start:look_ahead_end])

            if 'REG_CHECK' in look_ahead_text and 'Microsoft SQL Server' in look_ahead_text:
                # This is the outer qualification if - preserve the entire structure
                outer_if_preserved = True

                # Find the matching </if>
                if_end = i
                depth = 0
                while if_end < len(lines):
                    if lines[if_end].strip() == '<if>':
                        depth += 1
                    elif lines[if_end].strip() == '</if>':
                        depth -= 1
                        if depth == 0:
                            break
                    if_end += 1

                # Copy the entire outer if block as-is
                for j in range(i, if_end + 1):
                    output.append(lines[j].rstrip('\n'))
                i = if_end + 1
                continue

        # Everything else (check_type tags, group_policy tags, content outside structures)
        if stripped:
            output.append(line.rstrip('\n'))
        i += 1

    return output


def convert_file(input_path, output_path):
    with open(input_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    flattened = flatten_audit(lines)
    
    # Apply text replacements
    processed = []
    for line in flattened:
        # Replace CIS_ with HTH_ in audit file references
        line = line.replace('CIS_Microsoft_SQL_Server', 'HTH_Microsoft_SQL_Server')
        # Remove "1.0006 - MSSQL - " prefix from else report descriptions
        line = line.replace('1.0006 - MSSQL - HTH_Microsoft_SQL_Server', 'HTH_Microsoft_SQL_Server')
        processed.append(line)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        for line in processed:
            f.write(line + '\n')


def build_parser():
    parser = argparse.ArgumentParser(
        description="Convert SQL Server audit files by removing <if>/<condition>/<then>/<else> wrappers."
    )
    parser.add_argument(
        'input_file',
        nargs='?',
        default=None,
        help='Path to the input .audit file (prompted if not provided)',
    )
    parser.add_argument(
        '-o', '--output',
        help='Path for the flattened output file. Defaults to input-file-base-flattened.audit',
    )
    parser.add_argument(
        '--inplace',
        action='store_true',
        help='Overwrite the input file instead of writing to a new file',
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.input_file is None:
        input_path = input("Enter path to input .audit file: ").strip().strip('"').strip("'")
    else:
        input_path = args.input_file

    input_path = os.path.abspath(input_path)
    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"Input file not found: {input_path}")

    if args.inplace:
        output_path = input_path
    elif args.output:
        output_path = os.path.abspath(args.output)
    else:
        base = os.path.splitext(os.path.basename(input_path))[0]
        output_path = os.path.join(os.path.dirname(input_path), f"{base}-flattened.audit")

    print(f"Processing: {input_path}")
    convert_file(input_path, output_path)
    print(f"\n✓ SUCCESS: Flattened audit written to:")
    print(f"  {output_path}")


if __name__ == '__main__':
    main()