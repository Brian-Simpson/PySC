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
    - Extract items/custom_items from nested conditions
    - Inject report metadata (info, reference, see_also) into each item
    - Remove all <if>/<condition>/<then>/<else> wrappers and <report> blocks
    - Keep standalone items/custom_items/reports as-is
    """
    output = []
    pending_items = []
    i = 0

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Skip control flow tags
        if stripped in ('<if>', '</if>', '<then>', '</then>', '<else>', '</else>'):
            i += 1
            continue

        if stripped.startswith('<condition'):
            # Parse the condition and collect all items
            i += 1
            condition_items = []
            while i < len(lines) and lines[i].strip() != '</condition>':
                if lines[i].strip() in ('<item>', '<custom_item>'):
                    item, i = parse_item_block(lines, i)
                    condition_items.append(item)
                else:
                    i += 1
            i += 1  # skip </condition>
            pending_items = condition_items
            continue

        if stripped.startswith('<report'):
            # Parse report
            report, i = parse_report_block(lines, i)

            # If we have pending items from a condition, inject report fields into each
            if pending_items:
                for item in pending_items:
                    # Inject report metadata if not already present
                    if 'info' not in item and 'info' in report:
                        item['info'] = report['info']
                    if 'reference' not in item and 'reference' in report:
                        item['reference'] = report['reference']
                    if 'see_also' not in item and 'see_also' in report:
                        item['see_also'] = report['see_also']

                    # Write enriched item
                    if 'type' in item and item['type'] == 'OFFLINE_CONFIG_CHECK':
                        output.append('\n        <custom_item>')
                    else:
                        output.append('\n        <custom_item>')
                    for k, v in item.items():
                        output.append(f'                    {k:20}: {v}')
                    output.append('        </custom_item>')
                pending_items = []
            # Skip the report itself
            continue

        # Check for end of conditional blocks - if we have pending items and hit a control tag, output them
        if stripped in ('</then>', '</else>', '</if>') and pending_items:
            for item in pending_items:
                if 'type' in item and item['type'] == 'OFFLINE_CONFIG_CHECK':
                    output.append('\n        <custom_item>')
                else:
                    output.append('\n        <custom_item>')
                for k, v in item.items():
                    output.append(f'                    {k:20}: {v}')
                output.append('        </custom_item>')
            pending_items = []
            i += 1
            continue

        # Standalone items/custom_items (not in a condition)
        if stripped in ('<item>', '<custom_item>'):
            item, i = parse_item_block(lines, i)
            if 'type' in item and item['type'] == 'OFFLINE_CONFIG_CHECK':
                output.append('\n        <custom_item>')
            else:
                output.append('\n        <custom_item>')
            for k, v in item.items():
                output.append(f'                    {k:20}: {v}')
            output.append('        </custom_item>')
            continue

        # Everything else (check_type tags, content outside structures)
        if stripped:
            output.append(line.rstrip('\n'))
        i += 1

    return output


def convert_file(input_path, output_path):
    with open(input_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    flattened = flatten_audit(lines)

    # Write directly
    with open(output_path, 'w', encoding='utf-8') as f:
        for line in flattened:
            f.write(line + '\n')


def build_parser():
    parser = argparse.ArgumentParser(
        description="Convert F5 audit files by removing <if>/<condition>/<then>/<else> wrappers."
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