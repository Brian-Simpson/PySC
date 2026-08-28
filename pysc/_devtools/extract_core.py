"""One-time extraction tool: pull the normalization core out of the vendored
legacy monolith (pysc/_legacy/all_audits.py) into pysc/normalize/_core.py.

Approach: parse the monolith's AST, compute the transitive closure of
top-level definitions reachable from the normalization entry points, and emit
those definitions VERBATIM (original source lines, original order). Functions
belonging to excluded subsystems (catalog, merge, gap, threat-intel, CLI) are
reported if they end up in the closure so the boundary is explicit.

Run:  python -m pysc._devtools.extract_core [--dry-run]

After generation, _core.py becomes the hand-maintained home of the
normalization engine; this tool is kept for reference only.
"""

import ast
import sys
from pathlib import Path

PKG_ROOT = Path(__file__).resolve().parent.parent
SOURCE = PKG_ROOT / "_legacy" / "all_audits.py"
TARGET = PKG_ROOT / "normalize" / "_core.py"

# Entry points whose transitive dependencies define the normalization core.
SEEDS = [
    "process_file",
    "process_folder",
    "emit",
    "_write_parsing_results_for_folder",
    "_reset_validation_summary",
    "_print_validation_summary",
    "_timestamped_output_path",
    "determine_platform_from_filename",
    "extract_variables",
    "parse_document",
    "normalize_reference",
    "validate_and_repair_audit_file",
]

# Subsystems that should NOT be part of the normalize core. If the closure
# pulls any of these in, we print the offending dependency edge.
EXPECT_EXCLUDED_PREFIXES = (
    "generate_catalog",
    "match_unique_catalogs",
    "build_merged_master_audits",
    "run_production_gap_analysis",
    "_stage_gap_analysis_files",
    "_run_production_reference_gap_analysis",
    "_run_merged_audit_generation",
    "write_description_match_workbook",
    "main",
    "parse_cli_args",
    "write_docker_files",
)


def top_level_definitions(tree):
    """Map name -> top-level node defining it (functions, classes, constants)."""
    defs = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            defs.setdefault(node.name, node)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                for name in _target_names(target):
                    defs.setdefault(name, node)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            defs.setdefault(node.target.id, node)
    return defs


def _target_names(target):
    if isinstance(target, ast.Name):
        yield target.id
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            yield from _target_names(elt)


def referenced_names(node):
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def compute_closure(defs, seeds):
    included = {}
    why = {}  # name -> first referrer (for reporting)
    queue = [s for s in seeds if s in defs]
    missing_seeds = [s for s in seeds if s not in defs]
    while queue:
        name = queue.pop()
        if name in included:
            continue
        node = defs[name]
        included[name] = node
        for ref in sorted(referenced_names(node)):
            if ref in defs and ref not in included and ref != name:
                why.setdefault(ref, name)
                queue.append(ref)
    return included, why, missing_seeds


def main(argv=None):
    dry_run = "--dry-run" in (argv or sys.argv[1:])
    source_text = SOURCE.read_text(encoding="utf-8-sig")
    source_lines = source_text.splitlines(keepends=True)
    tree = ast.parse(source_text)

    defs = top_level_definitions(tree)
    included, why, missing_seeds = compute_closure(defs, SEEDS)

    if missing_seeds:
        print(f"WARNING: seeds not found: {missing_seeds}")

    # Report boundary violations (excluded subsystems pulled into the closure).
    violations = [n for n in included if n.startswith(EXPECT_EXCLUDED_PREFIXES)]
    for v in sorted(violations):
        chain = []
        cur = v
        while cur in why:
            chain.append(cur)
            cur = why[cur]
        chain.append(cur)
        print(f"BOUNDARY: {' <- '.join(chain)}")

    # Emit: module docstring note, all top-level imports, then included
    # definitions in original source order (deduped by node identity).
    import_nodes = [
        n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))
    ]
    # Guarded imports (try: import X / except: X = None) are ast.Try nodes;
    # include any top-level Try whose body contains an import.
    guarded_import_nodes = [
        n
        for n in tree.body
        if isinstance(n, ast.Try)
        and any(isinstance(b, (ast.Import, ast.ImportFrom)) for b in n.body)
    ]
    emit_nodes = {id(n): n for n in list(included.values())}
    ordered = sorted(emit_nodes.values(), key=lambda n: n.lineno)

    header = (
        '"""Normalization core, extracted VERBATIM from the legacy engine.\n'
        "\n"
        "Generated once by pysc/_devtools/extract_core.py from\n"
        "pysc/_legacy/all_audits.py; now hand-maintained. Definitions keep\n"
        "their original text and order. Catalog/merge/gap/threat-intel and CLI\n"
        "remain in the legacy module until their own extraction phases.\n"
        '"""\n\n'
    )

    chunks = [header]
    for node in import_nodes:
        chunks.append("".join(source_lines[node.lineno - 1 : node.end_lineno]))
    chunks.append("\n")
    for node in guarded_import_nodes:
        chunks.append("".join(source_lines[node.lineno - 1 : node.end_lineno]))
        chunks.append("\n")
    for node in ordered:
        # Include decorator lines if present.
        start = node.lineno - 1
        if getattr(node, "decorator_list", None):
            start = min(d.lineno for d in node.decorator_list) - 1
        chunks.append("".join(source_lines[start : node.end_lineno]))
        chunks.append("\n\n")

    output = "".join(chunks)

    n_funcs = sum(1 for n in ordered if isinstance(n, (ast.FunctionDef, ast.ClassDef)))
    n_consts = len(ordered) - n_funcs
    total_defs = len([n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))])
    print(
        f"Closure: {len(included)} names -> {len(ordered)} nodes "
        f"({n_funcs} functions/classes of {total_defs} in source, {n_consts} constants); "
        f"{len(output.splitlines())} lines."
    )

    excluded_funcs = sorted(
        n for n in defs
        if isinstance(defs[n], (ast.FunctionDef, ast.ClassDef)) and n not in included
    )
    print(f"Excluded functions ({len(excluded_funcs)}):")
    for name in excluded_funcs:
        print(f"  - {name}")

    if dry_run:
        print("(dry run: nothing written)")
        return

    TARGET.parent.mkdir(parents=True, exist_ok=True)
    TARGET.write_text(output, encoding="utf-8")
    print(f"Wrote {TARGET}")


if __name__ == "__main__":
    main()
