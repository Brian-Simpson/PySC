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
    normalize.apply_platform_overrides(cfg)
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


def cmd_gap_f5_compare(cfg, args):
    import os
    import time
    from pathlib import Path

    from pysc.gap.engine import _find_baseline_path
    from pysc.gap.f5compare import compare, splice_orphans, write_comparison_workbook

    folder = Path(args.dir)
    audit_files = sorted(p for p in folder.glob("*.audit") if p.is_file())
    baseline_name = args.baseline
    if not baseline_name:
        baseline_path = cfg.baseline_path("NetF5")
        baseline_name = baseline_path.name if baseline_path else None
    baseline = _find_baseline_path(audit_files, baseline_name)
    comparisons = [p for p in audit_files if p != baseline]

    result = compare(baseline, comparisons)
    print(f"Baseline  : {result['baseline_file']} ({result['baseline_active']} active F5 controls)")
    for r in result["results"]:
        print(f"  {r['file']}: active={r['active']} matching={r['matching']} orphaned={r['orphaned']}")

    stamp = time.strftime("%y%m%d%H%M")
    out = args.out or os.path.join(str(folder), f"Baseline_vs_CIS_Comparison_{stamp}.xlsx")
    write_comparison_workbook(result, out)
    print(f"Wrote {out}")

    if args.splice_orphans and result["orphans"]:
        spliced = splice_orphans(baseline, result["orphans"])
        print(f"Wrote {spliced}")


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


def _enterprise_result(cfg):
    from pysc.gap.enterprise import analyze_enterprise

    result = analyze_enterprise(cfg)
    for name in result.unmatched_candidates:
        print(f"[-] No platform mapping for candidate: {name}")
    return result


def _history_store(cfg):
    from pysc.history import HistoryStore

    return HistoryStore(cfg.path("history_db"))


def cmd_report(cfg, args):
    import os
    import time

    result = _enterprise_result(cfg)
    history = _history_store(cfg)
    try:
        if not args.no_snapshot:
            run_id = history.record_enterprise_run(result, notes=f"pysc report {args.format}")
            print(f"History snapshot recorded (run {run_id})")

        out_dir = cfg.path("report_output")
        out_dir.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%y%m%d%H%M")

        if args.format in ("matrix", "all"):
            from pysc.report.matrix import build_matrix

            out = args.out if (args.out and args.format == "matrix") else os.path.join(
                str(out_dir), f"Unified_Compliance_Matrix_{stamp}.xlsx"
            )
            build_matrix(result, out, history=history)
            print(f"Wrote {out}")

        if args.format in ("html", "all"):
            from pysc.report.html import build_dashboard

            out = args.out if (args.out and args.format == "html") else os.path.join(
                str(out_dir), f"dashboard_{stamp}.html"
            )
            build_dashboard(result, out, history=history)
            print(f"Wrote {out}")
    finally:
        history.close()


def cmd_history(cfg, args):
    history = _history_store(cfg)
    try:
        if args.history_command == "show":
            rows = history.platform_trend(args.platform)
            if not rows:
                print("No history recorded yet (run: pysc report all)")
                return
            print(f"{'Run':>4} {'Timestamp':<20} {'Platform':<10} "
                  f"{'Covered':>8} {'Recov':>6} {'Total':>6} {'Cov %':>7}")
            for run_id, ts, platform, covered, recoverable, total in rows:
                pct = round((covered / total) * 100, 2) if total else 0
                print(f"{run_id:>4} {ts:<20} {platform:<10} "
                      f"{covered:>8} {recoverable:>6} {total:>6} {pct:>6}%")
        elif args.history_command == "export":
            out = args.out or "coverage_history.csv"
            history.export_csv(out)
            print(f"Wrote {out}")
    finally:
        history.close()


def cmd_maturity(cfg, args):
    from pysc.maturity import (
        apply_proposals,
        load_pass_rates,
        propose,
        write_proposal_workbook,
    )

    threshold = (args.threshold if args.threshold is not None
                 else cfg.data.get("maturity", {}).get("pass_threshold", 90)) / 100.0

    rates = load_pass_rates(args.pass_rates)
    proposals, unmatched = propose(args.audit, rates, threshold)
    print(f"Export rows           : {len(rates)}")
    print(f"Below threshold       : {len(proposals) + len(unmatched)} "
          f"(threshold {round(threshold * 100, 1)}%)")
    print(f"Matching active checks: {len(proposals)}")
    if unmatched:
        print(f"No matching active check for {len(unmatched)} export row(s)")

    import os
    import time

    out_dir = cfg.path("report_output")
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%y%m%d%H%M")
    workbook = os.path.join(str(out_dir), f"Maturity_Proposals_{stamp}.xlsx")
    write_proposal_workbook(proposals, unmatched, threshold, workbook)
    print(f"Wrote {workbook}")

    if args.apply:
        if not proposals:
            print("Nothing to apply.")
            return
        out = apply_proposals(args.audit, proposals, args.out)
        print(f"Wrote matured audit: {out}")
        print("Commented checks will appear as recoverable coverage in the next gap run.")
    else:
        print("Proposal only (use --apply to write the matured audit).")


def cmd_download(cfg, args):
    from pysc.downloads import run as run_download

    run_download(
        cfg,
        apply=args.apply,
        keep_archive=not args.no_cache,
        all_variants=args.all,
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

    gf = gap_sub.add_parser(
        "f5-compare",
        help="F5 baseline vs CIS structural diff by (f5_command, json_transform) signature",
    )
    gf.add_argument("--dir", required=True, help="Folder with the F5 baseline + CIS audits")
    gf.add_argument("--baseline", help="Baseline filename (default: NetF5 profile from pysc.toml)")
    gf.add_argument("--splice-orphans", action="store_true",
                    help="Also write a baseline copy with orphaned controls spliced in")
    gf.add_argument("--out", help="Comparison workbook path")
    gf.set_defaults(func=cmd_gap_f5_compare)

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

    p = sub.add_parser(
        "report",
        help="Enterprise compliance reports (Excel matrix, HTML dashboard) + history snapshot",
    )
    p.add_argument("format", choices=["matrix", "html", "all"], help="Which report(s) to produce")
    p.add_argument("--out", help="Output path (single-format runs only)")
    p.add_argument("--no-snapshot", action="store_true", help="Skip recording a history snapshot")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("history", help="Coverage history (trend) inspection")
    hist_sub = p.add_subparsers(dest="history_command", required=True)
    hs = hist_sub.add_parser("show", help="Print per-run per-platform coverage")
    hs.add_argument("--platform", help="Filter to one platform code")
    hs.set_defaults(func=cmd_history)
    he = hist_sub.add_parser("export", help="Export coverage history to CSV")
    he.add_argument("--out", help="CSV path (default: coverage_history.csv)")
    he.set_defaults(func=cmd_history)

    p = sub.add_parser(
        "maturity",
        help="Propose/apply comment-outs for checks under the fleet pass-rate threshold",
    )
    p.add_argument("--audit", required=True, help="Baseline .audit file to mature")
    p.add_argument(
        "--pass-rates", required=True,
        help="Tenable results export (.xlsx with Description + Pass columns)",
    )
    p.add_argument(
        "--threshold", type=float,
        help="Pass-rate threshold in percent (default: [maturity].pass_threshold, 90)",
    )
    p.add_argument("--apply", action="store_true", help="Write the matured audit copy")
    p.add_argument("--out", help="Matured audit output path (with --apply)")
    p.set_defaults(func=cmd_maturity)

    p = sub.add_parser(
        "download",
        help="Fetch current vendor .audit benchmarks from Tenable downloads and stage new/updated ones",
    )
    p.add_argument("--apply", action="store_true",
                   help="Copy staged NEW/UPDATED files into audit_inputs (default: stage for review)")
    p.add_argument("--all", action="store_true",
                   help="Also stage platform-relevant benchmarks outside the curated families")
    p.add_argument("--no-cache", action="store_true",
                   help="Delete the downloaded archive after staging")
    p.set_defaults(func=cmd_download)

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
