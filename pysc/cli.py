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
    if args.engine == "legacy":
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
        return

    # New engine: pysc.normalize core for parse/normalize/validate; catalog and
    # merged-audit generation still delegate to the legacy module (Phase 3
    # extracts them). Flow mirrors legacy main() so outputs are identical.
    import os

    from pysc import normalize

    legacy = _legacy_session(cfg)
    normalize.reset_validation_summary()
    try:
        target = args.input.strip().strip('"').strip("'")
        if os.path.isdir(target):
            ok = normalize.process_folder(target, strict_mode=args.strict)
            print("\nGenerating controls catalog...")
            outp = legacy.generate_catalog(
                target, args.out_xlsx, os.path.join(target, "Normalized")
            )
            if args.export_duplicates:
                for p in legacy.export_duplicates_csvs(outp):
                    print(f"Wrote {p}")
            legacy._run_merged_audit_generation()
            normalize.write_parsing_results(target)
            if args.strict and not ok:
                raise RuntimeError(
                    "Strict mode: one or more files failed preflight/normalization."
                )
        elif os.path.isfile(target):
            ok = normalize.process_file(target, strict_mode=args.strict)
            if args.catalog:
                folder = os.path.dirname(target)
                print("\nGenerating controls catalog...")
                outp = legacy.generate_catalog(
                    folder, args.out_xlsx, os.path.join(folder, "Normalized")
                )
                if args.export_duplicates:
                    for p in legacy.export_duplicates_csvs(outp):
                        print(f"Wrote {p}")
            legacy._run_merged_audit_generation()
            normalize.write_parsing_results(os.path.dirname(target))
            if args.strict and not ok:
                raise RuntimeError("Strict mode: file failed preflight/normalization.")
        else:
            raise SystemExit(f"ERROR: Path does not exist: {target}")
    finally:
        normalize.print_validation_summary()


def cmd_run(cfg, args):
    argv = []
    if args.strict:
        argv.append("--strict")
    _run_legacy_main(cfg, argv)


def cmd_gap_production(cfg, args):
    legacy = _legacy_session(cfg)
    try:
        if args.stage:
            legacy._stage_gap_analysis_files()
        legacy.run_production_gap_analysis()
    finally:
        _finish_legacy(legacy)


def cmd_gap_platform(cfg, args):
    import time

    from pysc.gap import analyze_folder
    from pysc.gap.xlsx import export_workbook

    baseline = args.baseline
    if not baseline and args.platform:
        baseline_path = cfg.baseline_path(args.platform)
        if baseline_path is not None:
            baseline = baseline_path.name

    analysis = analyze_folder(
        args.dir,
        catalog_path=cfg.path("oscal_catalog"),
        baseline_name=baseline,
        profile=args.profile,
    )

    total = len(analysis.target_baseline)
    print(f"Baseline audit     : {analysis.baseline.short_name}")
    print(f"Candidate audits   : {len(analysis.candidates)}")
    print(
        f"Current coverage   : {analysis.baseline_coverage_count} / {total} "
        f"({round(analysis.baseline_coverage_count / total * 100, 2)}%)"
    )
    print(f"Opportunities      : {len(analysis.coverage_opportunities)}")
    print(f"  recoverable (un-comment) : {len(analysis.inactive_coverage_opportunities)}")
    print(f"  require new checks       : {len(analysis.additional_controls_not_present)}")

    if not args.no_xlsx:
        out = args.out
        if not out:
            import os

            stamp = time.strftime("%y%m%d%H%M")
            out = os.path.join(args.dir, f"NIST_Gap_Analysis_{stamp}.xlsx")
        export_workbook(analysis, out)
        print(f"Wrote {out}")


def cmd_gap_harvest(cfg, args):
    from pysc.gap import harvest

    baseline = args.baseline
    if not baseline and args.platform:
        baseline_path = cfg.baseline_path(args.platform)
        if baseline_path is not None:
            baseline = str(baseline_path)

    out, count, skipped = harvest(
        args.dir,
        controls_file=args.controls,
        baseline_path=baseline,
        output_file=args.out,
    )
    for row in skipped:
        print(
            f"[SKIP] {row['nist_ref']} {row['rule_id']} covered by baseline "
            f"control {row['covered_by']}"
        )
    print(f"Gaps harvested : {count}")
    print(f"Output file    : {out}")


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
    p.add_argument(
        "--engine",
        choices=["new", "legacy"],
        default="new",
        help="Normalization engine (default: new; 'legacy' is the vendored parity oracle)",
    )
    p.set_defaults(func=cmd_normalize)

    p = sub.add_parser("run", help="Full pipeline: production + vendor inputs, catalogs, crosswalk, merge, gap")
    p.add_argument("--strict", action="store_true")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("gap", help="NIST 800-53 gap analysis")
    gap_sub = p.add_subparsers(dest="gap_command", required=True)

    gp = gap_sub.add_parser(
        "platform",
        help="Baseline vs candidate audits for one platform (OSCAL catalog, recoverable coverage)",
    )
    gp.add_argument("--dir", required=True, help="Folder of .audit files (e.g. Gap\\MSSRV)")
    gp.add_argument("--platform", help="Platform code from pysc.toml (supplies the baseline name)")
    gp.add_argument("--baseline", help="Baseline audit filename (overrides --platform lookup)")
    gp.add_argument(
        "--profile",
        choices=["full", "high", "moderate", "low"],
        default="full",
        help="Target baseline profile (only 'full' is available)",
    )
    gp.add_argument("--out", help="Output workbook path (default: <dir>\\NIST_Gap_Analysis_<ts>.xlsx)")
    gp.add_argument("--no-xlsx", action="store_true", help="Print summary only")
    gp.set_defaults(func=cmd_gap_platform)

    gpr = gap_sub.add_parser(
        "production", help="Whole-estate reference gap analysis (legacy engine)"
    )
    gpr.add_argument("--stage", action="store_true", help="Re-stage For_Gap combined audits first")
    gpr.set_defaults(func=cmd_gap_production)

    gh = gap_sub.add_parser(
        "harvest", help="Pull gap-closing checks from candidate audits into a paste-ready .audit"
    )
    gh.add_argument("--dir", required=True, help="Folder of candidate .audit files")
    gh.add_argument("--controls", help="Controls list file (default: <dir>\\controls.txt)")
    gh.add_argument("--platform", help="Platform code from pysc.toml (supplies the baseline for suppression)")
    gh.add_argument("--baseline", help="Baseline audit path for suppression (overrides --platform)")
    gh.add_argument("--out", help="Output path (default: <dir>\\normalized_custom_items.audit)")
    gh.set_defaults(func=cmd_gap_harvest)

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
