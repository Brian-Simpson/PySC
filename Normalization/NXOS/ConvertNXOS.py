#!/usr/bin/env python3
import argparse
import os
import re
from collections import OrderedDict


def parse_item_block(lines, start_idx):
    """Parse an <item>...</item> block starting at start_idx. Return (dict, end_idx)."""
    item = OrderedDict()
    i = start_idx
    while i < len(lines):
        line = lines[i].strip()
        if line == '</item>':
            return item, i + 1
        if line.startswith('<item'):
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
    - Extract items from nested conditions
    - Inject report metadata (info, reference, see_also) into each item
    - Remove all <if>/<condition>/<then>/<else> wrappers and <report> blocks
    - Keep standalone items as-is
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
            print(f"DEBUG: Found condition at line {i}")
            # Parse the condition and collect all items
            i += 1
            condition_items = []
            while i < len(lines) and lines[i].strip() != '</condition>':
                if lines[i].strip() == '<item>':
                    print(f"DEBUG: Found item in condition at line {i}")
                    item, i = parse_item_block(lines, i)
                    condition_items.append(item)
                else:
                    i += 1
            i += 1  # skip </condition>
            pending_items = condition_items
            print(f"DEBUG: Collected {len(pending_items)} items from condition")
            continue
        
        if stripped.startswith('<report'):
            print(f"DEBUG: Skipping report at line {i}: {stripped}")
            # Parse report but skip it entirely - we don't want any reports in the output
            report, i = parse_report_block(lines, i)
            continue
        
        # Check for end of conditional blocks - if we have pending items and hit a control tag, output them
        if stripped in ('</then>', '</else>', '</if>') and pending_items:
            print(f"DEBUG: End of condition block, outputting {len(pending_items)} pending items")
            for item in pending_items:
                output.append('\n        <item>')
                for k, v in item.items():
                    output.append(f'                    {k:20}: {v}')
                output.append('        </item>')
            pending_items = []
            i += 1
            continue
        
        # Standalone items (not in a condition)
        if stripped == '<item>':
            item, i = parse_item_block(lines, i)
            output.append('\n        <item>')
            for k, v in item.items():
                output.append(f'                    {k:20}: {v}')
            output.append('        </item>')
            continue
        
        # Everything else (check_type tags, content outside structures)
        if stripped:
            print(f"DEBUG: Adding line: {stripped[:50]}...")
            output.append(line.rstrip('\n'))
        i += 1
    
    return output


def convert_file(input_path, output_path):
    with open(input_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    flattened = flatten_audit(lines)
    
    print(f"DEBUG: Writing {len(flattened)} lines to {output_path}")
    for i, line in enumerate(flattened[:5]):
        print(f"  Line {i}: {repr(line)}")

    # Write directly
    with open(output_path, 'w', encoding='utf-8') as f:
        for line in flattened:
            f.write(line + '\n')
    
    print(f"DEBUG: File written, checking size...")
    import os
    size = os.path.getsize(output_path)
    print(f"DEBUG: File size: {size} bytes")


def build_parser():
    parser = argparse.ArgumentParser(
        description="Convert NX-OS audit files by removing <if>/<condition>/<then>/<else> wrappers."
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
