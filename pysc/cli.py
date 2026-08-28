"""pysc command-line interface.

Phase 1: every subcommand is a thin delegate into the vendored legacy engine
(pysc/_legacy/all_audits.py). Delegation happens by rebuilding the argv the
legacy parse_cli_args() expects, so behavior is identical to running
ALL_AUDITS.py directly. Later phases replace delegates with native modules.
"""

import argparse
import sys

from pysc import __version__
from pysc.config import ConfigError, load_config, load_legacy


def _legacy_session(cfg):
    legacy = load_legacy(cfg)
    legacy._reset_validation_summary()
    return legacy


def _finish_legacy(legacy):
    legacy._print_validation_summary()


def _run_legacy_main(cfg, argv):
    """Invoke legacy main() with a reconstructed sys.argv."""
    legacy = _legacy_session(cfg)
    old_argv = sys.argv
    sys.argv = ["ALL_AUDITS.py"] + argv
    try:
        legacy.main()
    finally:
        sys.argv = old_argv
        _finish_legacy(legacy)


def cmd_normalize(cfg, args):
    argv = [args.input]
    if args.out_xlsx:
        argv.append(args.out_xlsx)
    if args.catalog:
        argv.append("--catalog")
    if args.export_duplicates:
        argv.append("--export-duplicates")
    if args.strict:
        argv.append("--strict")
    _run_legacy_main(cfg, argv)


def cmd_run(cfg, args):
    argv = []
    if args.strict:
        argv.append("--strict")
    _run_legacy_main(cfg, argv)


def cmd_gap(cfg, args):
    legacy = _legacy_session(cfg)
    try:
        if args.stage:
            legacy._stage_gap_analysis_files()
        legacy.run_production_gap_analysis()
    finally:
        _finish_legacy(legacy)


def cmd_catalog(cfg, args):
    import os

    legacy = _legacy_session(cfg)
    try:
        folder = args.input or str(cfg.path("vendor_inputs"))
        outp = legacy.generate_catalog(
            folder, args.out_xlsx, os.path.join(folder, "Normalized")
        )
        if args.export_duplicates:
            for p in legacy.export_duplicates_csvs(outp):
                print(f"Wrote {p}")
    finally:
        _finish_legacy(legacy)


def cmd_match_catalogs(cfg, args):
    import os

    legacy = _legacy_session(cfg)
    try:
        left = args.left or legacy._resolve_existing_or_latest_timestamped_path(
            os.path.join(str(cfg.path("normalized")), "Unique_Controls_Catalog.xlsx")
        )
        right = args.right or legacy._resolve_existing_or_latest_timestamped_path(
            os.path.join(str(cfg.path("vendor_inputs")), "Normalized", "Unique_Controls_Catalog.xlsx")
        )
        legacy.match_unique_catalogs(left, right, args.out)
        legacy._run_merged_audit_generation()
    finally:
        _finish_legacy(legacy)


def cmd_validate(cfg, args):
    legacy = _legacy_session(cfg)
    try:
        code, output = legacy._run_check_audit_in_docker(args.audit)
        if code == 0:
            print(f"check_audit passed: {args.audit}")
        elif code == 127:
            print(f"check_audit skipped: {output}")
        else:
            print(f"check_audit FAILED ({code}): {args.audit}")
            if output:
                print(output)
        sys.exit(0 if code in (0, 127) else 1)
    finally:
        _finish_legacy(legacy)


def cmd_threat_intel(cfg, args):
    legacy = load_legacy(cfg)
    data = legacy._load_threat_intel_cache(force_refresh=args.refresh)
    taxonomy = len(data.get("control_taxonomy", []) or [])
    overrides = len((data.get("threat_by_control_id", {}) or {}).keys())
    print(
        f"Threat intel: taxonomy={taxonomy} | external_overrides={overrides} | "
        f"source={data.get('source', 'builtin')}"
    )


def build_parser():
    parser = argparse.ArgumentParser(
        prog="pysc",
        description="HTH Tenable .audit file management: normalize, gap-analyze, report.",
    )
    parser.add_argument("--version", action="version", version=f"pysc {__version__}")
    parser.add_argument("--config", help="Path to pysc.toml (default: search upward from cwd)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("normalize", help="Normalize .audit file(s) into HTH baseline format")
    p.add_argument("input", help="Audit file or folder")
    p.add_argument("--out-xlsx", help="Catalog workbook output path")
    p.add_argument("--catalog", action="store_true", help="Also generate controls catalog (file mode)")
    p.add_argument("--export-duplicates", action="store_true")
    p.add_argument("--strict", action="store_true", help="Fail on any preflight/normalization error")
    p.set_defaults(func=cmd_normalize)

    p = sub.add_parser("run", help="Full pipeline: production + vendor inputs, catalogs, crosswalk, merge, gap")
    p.add_argument("--strict", action="store_true")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("gap", help="Production NIST reference gap analysis")
    p.add_argument("--stage", action="store_true", help="Re-stage For_Gap combined audits first")
    p.set_defaults(func=cmd_gap)

    p = sub.add_parser("catalog", help="Generate controls catalog workbook for a folder")
    p.add_argument("input", nargs="?", help="Audit folder (default: vendor_inputs)")
    p.add_argument("--out-xlsx")
    p.add_argument("--export-duplicates", action="store_true")
    p.set_defaults(func=cmd_catalog)

    p = sub.add_parser("match-catalogs", help="Cross-match two Unique_Controls_Catalog workbooks")
    p.add_argument("left", nargs="?")
    p.add_argument("right", nargs="?")
    p.add_argument("out", nargs="?")
    p.set_defaults(func=cmd_match_catalogs)

    p = sub.add_parser("validate", help="Run Tenable check_audit (Docker) against one .audit file")
    p.add_argument("audit")
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("threat-intel", help="Show or refresh the threat-intel cache")
    p.add_argument("--refresh", action="store_true")
    p.set_defaults(func=cmd_threat_intel)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        parser.error(str(exc))
    args.func(cfg, args)


if __name__ == "__main__":
    main()
