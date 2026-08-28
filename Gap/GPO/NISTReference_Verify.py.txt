import argparse
import json
import re
import shlex
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def ask_for_files() -> Tuple[List[str], Dict[str, Optional[str]]]:
    prompt = 'Enter path(s) to audit file(s) to verify, separated by commas; optional flags may follow: '
    raw = input(prompt).strip()
    
    # Standardize Windows slashes to prevent shlex token escape failures
    raw = raw.replace('\\', '/')
    
    tokens = shlex.split(raw)
    files: List[str] = []
    options: Dict[str, Optional[str]] = {}
    i = 0
    while i < len(tokens):
        token = tokens[i].rstrip(',')
        if token.startswith('--'):
            if token in ('--fix', '--backup', '--yes', '--show-blocks'):
                options[token] = 'true'
            elif token in ('--mapping', '--placeholder'):
                i += 1
                if i < len(tokens):
                    options[token] = tokens[i]
                else:
                    options[token] = None
            else:
                print(f'Warning: unsupported option ignored: {token}')
        else:
            files.append(token)
        i += 1
    return files, options


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Verify and optionally fix NIST references dynamically via the official live NIST 800-53r5 OSCAL Framework.'
    )
    parser.add_argument(
        'files',
        nargs='*',
        help='Path(s) to one or more audit file(s) to verify.',
    )
    parser.add_argument(
        '--fix',
        action='store_true',
        help='Prompt to add or correct missing/incomplete reference metadata using dynamic web lookups.',
    )
    parser.add_argument(
        '--mapping',
        help='JSON file mapping descriptions to reference strings for automatic override fixes.',
    )
    parser.add_argument(
        '--placeholder',
        help='Placeholder reference value to use for missing entries when lookups yield no text matches.',
    )
    parser.add_argument(
        '--backup',
        action='store_true',
        help='Create a .bak backup of the original file before writing fixes.',
    )
    parser.add_argument(
        '--yes',
        action='store_true',
        help='Apply automatic framework fixes without prompting when keyword lookups yield a high-confidence match.',
    )
    parser.add_argument(
        '--show-blocks',
        action='store_true',
        help='Print block context for missing or incomplete references.',
    )
    return parser.parse_args()


def load_file(path: Path) -> str:
    if not path.exists():
        raise FileNotFoundError(f'File not found: {path}')
    return path.read_text(encoding='utf-8', errors='ignore')


def save_file(path: Path, text: str, backup: bool = False) -> None:
    if backup:
        backup_path = path.with_suffix(path.suffix + '.bak')
        backup_path.write_text(path.read_text(encoding='utf-8', errors='ignore'), encoding='utf-8')
        print(f'Backup created: {backup_path}')
    path.write_text(text, encoding='utf-8')


def load_mapping(path: str) -> Dict[str, str]:
    mapping_path = Path(path)
    if not mapping_path.exists():
        raise FileNotFoundError(f'Mapping file not found: {mapping_path}')
    data = mapping_path.read_text(encoding='utf-8', errors='ignore')
    mapping = json.loads(data)
    if not isinstance(mapping, dict):
        raise ValueError('Mapping file must contain a JSON object of description->reference pairs.')
    return {str(k).strip(): str(v).strip() for k, v in mapping.items()}


def find_custom_blocks(text: str) -> List[Dict[str, object]]:
    matches = []
    for match in re.finditer(r'<custom_item>.*?</custom_item>', text, re.DOTALL):
        matches.append({'text': match.group(0), 'start': match.start(), 'end': match.end()})
    return matches


def extract_description(block: str) -> str:
    match = re.search(r'(?:#\s*)?description\s*:\s*"([^"]*)"', block)
    return match.group(1).strip() if match else 'NO_DESCRIPTION'


def extract_reference(block: str) -> Optional[str]:
    match = re.search(r'(?:#\s*)?reference\s*:\s*"([^"]*)"', block)
    return match.group(1).strip() if match else None


def extract_info_line(block: str) -> Optional[re.Match]:
    return re.search(r'^(?P<indent>[ \t]*)(info\s*:\s*"[^"]*")\s*$', block, re.MULTILINE)


def extract_info_text(block: str) -> Optional[str]:
    match = re.search(r'(?:#\s*)?info\s*:\s*"([^"]*)"', block)
    return match.group(1).strip() if match else None


def normalize_text(text: str) -> List[str]:
    """Splits target string descriptive metadata into search-optimized keyword sequences."""
    if not text:
        return []
    text = text.lower()
    # Strip audit configuration file tags ('1.0255 - mswrk - ')
    text = re.sub(r'^\d+(\.\d+)*\s*-\s*[a-z0-9_-]+\s*-\s*', '', text)
    # Remove characters that aren't letters or numbers
    text = re.sub(r'[^a-z0-9\s]', ' ', text)
    return [word for word in text.split() if len(word) > 3]  # Drop useless noise filler words


def infer_reference_from_block(block: str, source_lookup: List[Dict[str, object]]) -> Optional[str]:
    """Scans the downloaded active NIST controls matrix via granular token intersection arrays."""
    description = extract_description(block)
    info_text = extract_info_text(block)
    
    desc_tokens = normalize_text(description)
    info_tokens = normalize_text(info_text)
    combined_search_tokens = list(set(desc_tokens + info_tokens))
    
    if not combined_search_tokens:
        return None

    best_control = None
    max_matches = 0

    # Crawl the live NIST control descriptions for common security signatures
    for control in source_lookup:
        id_str = control.get("id", "").upper()
        title_str = control.get("title", "").lower()
        desc_str = control.get("description", "").lower()
        
        # Check text overlap criteria across data spaces
        match_count = sum(1 for token in combined_search_tokens if token in title_str or token in desc_str)
        
        # Exact control ID matching logic if a string pattern matches a raw control family name
        if any(token.upper() in id_str for token in combined_search_tokens if len(token) == 4 and '-' in token):
            return f"NIST 800-53r5|{id_str}"

        if match_count > max_matches:
            max_matches = match_count
            best_control = id_str

    # Only accept high-confidence token intersections to prevent false assignments
    return f"NIST 800-53r5|{best_control}" if max_matches >= 2 else None


def is_reference_incomplete(value: str) -> bool:
    return value == 'NIST 800-53r5|' or value == 'NIST 800-53r5' or value.endswith('|')


def normalize_reference_line(reference: str, indent: str = '          ') -> str:
    return f'{indent}reference         : "{reference}"'


def block_needs_fix(reference: Optional[str]) -> bool:
    return reference is None or is_reference_incomplete(reference)


def print_summary(file_path: Path, total: int, missing: List[Tuple[str, str]], incomplete: List[Tuple[str, str]]) -> None:
    print(f'File: {file_path}')
    print(f'  Total blocks with missing or incomplete references: {total}')
    print(f'    Missing reference entries: {len(missing)}')
    print(f'    Incomplete reference entries: {len(incomplete)}')
    print()


def print_block_context(block: str) -> None:
    lines = block.strip().splitlines()
    for line in lines:
        if any(k in line for k in ('description', 'info', 'reference', 'see_also', 'type')):
            print(line)
    print('---')


def generate_fix_value(description: str, block: str, current_ref: Optional[str], mapping: Dict[str, str], source_lookup: List[Dict[str, object]], placeholder: Optional[str], yes: bool) -> Optional[str]:
    if description in mapping:
        return mapping[description]
    inferred = infer_reference_from_block(block, source_lookup)
    if inferred:
        return inferred
    if placeholder is not None:
        return placeholder
    if yes:
        return None
    prompt = f'Enter reference for "{description}"'
    prompt += f' [current: {current_ref}]' if current_ref is not None else ''
    prompt += ' (leave blank to skip): '
    value = input(prompt).strip()
    return value or None


def fix_block_reference(block: str, reference: str) -> str:
    reference_line = re.search(r'^[ \t]*reference\s*:\s*"([^"]*)"\s*$', block, re.MULTILINE)
    if reference_line:
        indent = re.match(r'^[ \t]*', reference_line.group(0)).group(0)
        return block[:reference_line.start()] + normalize_reference_line(reference, indent) + block[reference_line.end():]

    info_match = extract_info_line(block)
    if info_match:
        insert_text = '\n' + normalize_reference_line(reference, info_match.group('indent'))
        insert_pos = info_match.end()
        return block[:insert_pos] + insert_text + block[insert_pos:]

    return block


def apply_fixes(text: str, blocks: List[Dict[str, object]], updates: Dict[int, str]) -> str:
    if not updates:
        return text
    result = []
    last_end = 0
    for idx, block_info in enumerate(blocks):
        result.append(text[last_end:block_info['start']])
        block_text = block_info['text']
        if idx in updates:
            block_text = fix_block_reference(block_text, updates[idx])
        result.append(block_text)
        last_end = block_info['end']
    result.append(text[last_end:])
    return ''.join(result)


def download_live_nist_catalog() -> List[Dict[str, object]]:
    """Downloads the official live NIST 800-53r5 OSCAL catalog file and flattens it for query use."""
    # Live URL to the official NIST group schema definitions on GitHub
    url = "https://githubusercontent.com"
    print("Connecting to official NIST repository to parse live framework definitions...")
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read().decode('utf-8'))
        
        flat_controls = []
        catalog = data.get("catalog", {})
        
        # Flatten the nested groups structure into a standardized array profile
        for group in catalog.get("groups", []):
            for ctrl in group.get("controls", []):
                control_data = {
                    "id": ctrl.get("id", ""),
                    "title": ctrl.get("title", ""),
                    "description": ""
                }
                # Capture the core summary prose inside the definition array
                parts = []
                for part in ctrl.get("parts", []):
                    for prose in part.get("prose", []):
                        parts.append(prose)
                control_data["description"] = " ".join(parts)
                flat_controls.append(control_data)
                
        print(f"Successfully loaded and cached {len(flat_controls)} controls directly from NIST.\n")
        return flat_controls
    except Exception as e:
        print(f"Warning: Could not connect to NIST web database: {e}. Fallback logic enabled.")
        return []


def analyze_file(text: str) -> Tuple[int, List[Tuple[str, str]], List[Tuple[str, str]], List[Dict[str, object]]]:
    blocks = find_custom_blocks(text)
    missing = []
    incomplete = []

    for block_info in blocks:
        block = block_info['text']
        desc = extract_description(block)
        ref = extract_reference(block)
        if ref is None:
            missing.append((desc, block))
        elif is_reference_incomplete(ref):
            incomplete.append((desc, ref))

    total = len(missing) + len(incomplete)
    return total, missing, incomplete, blocks


def main() -> None:
    args = parse_args()
    if not args.files:
        files, options = ask_for_files()
        args.files = files
        if options.get('--fix') == 'true':
            args.fix = True
        if options.get('--backup') == 'true':
            args.backup = True
        if options.get('--yes') == 'true':
            args.yes = True
        if options.get('--show-blocks') == 'true':
            args.show_blocks = True
        if options.get('--mapping') is not None:
            args.mapping = options.get('--mapping')
        if options.get('--placeholder') is not None:
            args.placeholder = options.get('--placeholder')
        if not args.files:
            print('No files specified. Exiting.')
            return

    mapping = {}
    if args.mapping:
        try:
            mapping = load_mapping(args.mapping)
        except Exception as exc:
            print(f'Error loading mapping file: {exc}')
            return

    # In-memory streaming instantiation
    nist_catalog_cache = download_live_nist_catalog() if args.fix else []

    for file_path_str in args.files:
        path = Path(file_path_str)
        try:
            text = load_file(path)
        except Exception as exc:
            print(f'Error reading file {path}: {exc}')
            continue

        total, missing, incomplete, blocks = analyze_file(text)
        print_summary(path, total, missing, incomplete)

        if args.show_blocks and (missing or incomplete):
            print('Block context for missing/incomplete references:')
            for desc, block in missing:
                print(f'DESCRIPTION: {desc}')
                print_block_context(block)
            for desc, ref in incomplete:
                print(f'DESCRIPTION: {desc} => {ref}')
                block = next(b['text'] for b in blocks if extract_description(b['text']) == desc)
                print_block_context(block)

        if args.fix and (missing or incomplete):
            updates: Dict[int, str] = {}
            for idx, block_info in enumerate(blocks):
                desc = extract_description(block_info['text'])
                block_text = block_info['text']
                ref = extract_reference(block_text)
                if not block_needs_fix(ref):
                    continue
                new_ref = generate_fix_value(desc, block_text, ref, mapping, nist_catalog_cache, args.placeholder, args.yes)
                if new_ref:
                    updates[idx] = new_ref
                    print(f'Fixing "{desc}" => "{new_ref}"')

            if updates:
                if args.backup:
                    save_file(path, text, backup=True)
                    text = load_file(path)
                fixed_text = apply_fixes(text, blocks, updates)
                save_file(path, fixed_text, backup=False)
                print(f'Updated {len(updates)} block(s) in {path}.')
            else:
                print('No automatic fixes were applied.')
        elif not args.fix and (missing or incomplete):
            print('Run with --fix to add or correct missing references.')


if __name__ == '__main__':
    main()
