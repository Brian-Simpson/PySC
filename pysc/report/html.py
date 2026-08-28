"""Self-contained HTML compliance dashboard.

One portable file (inline CSS, no external assets, no JS dependencies) suitable
for posting to SharePoint/intranet. Charts are pure HTML/SVG: a horizontal bar
list for per-platform coverage, a platform x NIST-family heatmap table with
visible values (doubles as the table view), and a coverage trend line from the
history DB. Colors follow the validated reference palette (single blue series;
sequential blue ramp; status colors only for labeled state chips), with dark
mode via prefers-color-scheme using the palette's documented dark steps.
"""

import html as _html
import time
from collections import defaultdict

from pysc.nist.oscal import OscalCatalog

# Sequential blue ramp (light mode), step 100 -> 700, from the reference palette.
_RAMP = [
    "#cde2fb", "#b7d3f6", "#9ec5f4", "#86b6ef", "#6da7ec", "#5598e7",
    "#3987e5", "#2a78d6", "#256abf", "#1c5cab", "#184f95", "#104281", "#0d366b",
]

_CSS = """
:root { color-scheme: light dark; }
body {
  margin: 0; padding: 24px;
  font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
  background: #f9f9f7; color: #0b0b0b;
}
.viz-root {
  --surface-1: #fcfcfb; --text-primary: #0b0b0b; --text-secondary: #52514e;
  --muted: #898781; --grid: #e1e0d9; --baseline: #c3c2b7;
  --series-1: #2a78d6; --good: #0ca30c; --critical: #d03b3b; --serious: #ec835a;
  --border: rgba(11,11,11,0.10);
}
@media (prefers-color-scheme: dark) {
  body { background: #0d0d0d; color: #ffffff; }
  .viz-root {
    --surface-1: #1a1a19; --text-primary: #ffffff; --text-secondary: #c3c2b7;
    --muted: #898781; --grid: #2c2c2a; --baseline: #383835;
    --series-1: #3987e5; --border: rgba(255,255,255,0.10);
  }
}
h1 { font-size: 20px; margin: 0 0 4px; }
.subtitle { color: var(--text-secondary); font-size: 13px; margin-bottom: 20px; }
section {
  background: var(--surface-1); border: 1px solid var(--border);
  border-radius: 8px; padding: 16px 20px; margin-bottom: 16px;
}
h2 { font-size: 14px; margin: 0 0 12px; color: var(--text-primary); }
.tiles { display: flex; gap: 16px; flex-wrap: wrap; }
.tile { flex: 1 1 140px; }
.tile .value { font-size: 32px; font-weight: 600; }
.tile .label { font-size: 12px; color: var(--text-secondary); margin-top: 2px; }
.bar-row { display: grid; grid-template-columns: 90px 1fr 110px; gap: 8px; align-items: center; margin: 6px 0; font-size: 13px; }
.bar-track { background: transparent; border-left: 2px solid var(--baseline); height: 16px; position: relative; }
.bar-fill { background: var(--series-1); height: 100%; border-radius: 0 4px 4px 0; min-width: 2px; }
.bar-val { color: var(--text-secondary); font-variant-numeric: tabular-nums; }
table { border-collapse: collapse; font-size: 12px; width: 100%; }
th, td { padding: 5px 8px; text-align: right; border: 1px solid var(--grid); }
th { color: var(--text-secondary); font-weight: 600; }
td.rowhead, th.rowhead { text-align: left; font-weight: 600; }
td.heat { font-variant-numeric: tabular-nums; }
.chip { display: inline-block; padding: 1px 8px; border-radius: 10px; font-size: 11px; font-weight: 600; }
.chip.missing { border: 1px solid var(--critical); color: var(--critical); }
.chip.nobaseline { border: 1px solid var(--serious); color: var(--serious); }
.legend-note { color: var(--muted); font-size: 11px; margin-top: 8px; }
svg text { fill: var(--text-secondary); font-size: 11px; }
footer { color: var(--muted); font-size: 11px; margin-top: 12px; }
"""


def _esc(value):
    return _html.escape(str(value))


def _pct(part, whole):
    return round((part / whole) * 100, 2) if whole else 0.0


def _heat_style(pct):
    """Sequential ramp cell: light ink on dark steps, dark ink on light steps."""
    idx = min(int(pct / 100 * (len(_RAMP) - 1)), len(_RAMP) - 1)
    color = _RAMP[idx]
    ink = "#0b0b0b" if idx < 7 else "#ffffff"
    return f"background:{color};color:{ink}"


def _platform_rows(result):
    rows = []
    for code, analysis in sorted(result.analyses.items()):
        total = len(analysis.target_baseline)
        rows.append(
            {
                "code": code,
                "baseline": analysis.baseline.short_name,
                "active": analysis.baseline.checks_parsed,
                "inactive": len(analysis.baseline.inactive_checks),
                "covered": analysis.baseline_coverage_count,
                "total": total,
                "pct": _pct(analysis.baseline_coverage_count, total),
                "recoverable": len(analysis.inactive_coverage_opportunities),
                "additional": len(analysis.additional_controls_not_present),
            }
        )
    return rows


def _family_grid(result):
    families = set()
    grid = {}
    for code, analysis in sorted(result.analyses.items()):
        by_family = defaultdict(lambda: {"total": 0, "covered": 0})
        for control_id in analysis.target_baseline:
            family, _ = OscalCatalog.family_of(control_id)
            by_family[family]["total"] += 1
            if control_id in analysis.baseline_covered_set:
                by_family[family]["covered"] += 1
        grid[code] = {
            fam: _pct(b["covered"], b["total"]) for fam, b in by_family.items()
        }
        families.update(by_family.keys())
    return sorted(families), grid


def _trend_svg(history):
    """Overall enterprise coverage % per run as a single blue line."""
    if history is None:
        return "", 0
    per_run = defaultdict(lambda: [0, 0])  # run -> [covered, total]
    labels = {}
    for run_id, ts, _platform, covered, _recoverable, total in history.platform_trend():
        per_run[run_id][0] += covered or 0
        per_run[run_id][1] += total or 0
        labels[run_id] = ts
    points = [
        (run_id, _pct(c, t)) for run_id, (c, t) in sorted(per_run.items()) if t
    ]
    if len(points) < 2:
        return "", len(points)

    width, height, pad = 640, 160, 30
    max_pct = max(p[1] for p in points) * 1.25 or 1
    step_x = (width - 2 * pad) / (len(points) - 1)
    coords = []
    for i, (_run, pct) in enumerate(points):
        x = pad + i * step_x
        y = height - pad - (pct / max_pct) * (height - 2 * pad)
        coords.append((round(x, 1), round(y, 1)))
    polyline = " ".join(f"{x},{y}" for x, y in coords)
    dots = "".join(
        f'<circle cx="{x}" cy="{y}" r="4" fill="var(--series-1)">'
        f"<title>run {run}: {pct}%</title></circle>"
        for (x, y), (run, pct) in zip(coords, points)
    )
    tick_labels = "".join(
        f'<text x="{x}" y="{height - 8}" text-anchor="middle">{_esc(labels[run][:10])}</text>'
        for (x, _y), (run, _pct_) in zip(coords, points)
    )
    return (
        f'<svg viewBox="0 0 {width} {height}" role="img" '
        f'aria-label="Enterprise coverage trend">'
        f'<line x1="{pad}" y1="{height - pad}" x2="{width - pad}" y2="{height - pad}" '
        f'stroke="var(--baseline)" stroke-width="1"/>'
        f'<polyline points="{polyline}" fill="none" stroke="var(--series-1)" stroke-width="2"/>'
        f"{dots}{tick_labels}</svg>",
        len(points),
    )


def build_dashboard(result, output_file, history=None):
    rows = _platform_rows(result)
    families, grid = _family_grid(result)
    trend_svg, trend_points = _trend_svg(history)

    covered_sum = sum(r["covered"] for r in rows)
    total_sum = sum(r["total"] for r in rows)
    recoverable_sum = sum(r["recoverable"] for r in rows)
    additional_sum = sum(r["additional"] for r in rows)

    tiles = f"""
    <section><div class="tiles">
      <div class="tile"><div class="value">{len(rows)}</div>
        <div class="label">Platforms with baselines</div></div>
      <div class="tile"><div class="value">{_pct(covered_sum, total_sum)}%</div>
        <div class="label">Base-control coverage (all platforms)</div></div>
      <div class="tile"><div class="value">{recoverable_sum}</div>
        <div class="label">Gaps recoverable by un-commenting</div></div>
      <div class="tile"><div class="value">{additional_sum}</div>
        <div class="label">Gaps requiring new checks</div></div>
      <div class="tile"><div class="value">{len(result.missing_baseline)}</div>
        <div class="label">Platforms without a baseline</div></div>
    </div></section>"""

    max_pct = max((r["pct"] for r in rows), default=1) or 1
    bar_rows = "".join(
        f'<div class="bar-row"><div>{_esc(r["code"])}</div>'
        f'<div class="bar-track"><div class="bar-fill" '
        f'style="width:{max(r["pct"] / max_pct * 100, 0.5)}%" '
        f'title="{_esc(r["code"])}: {r["covered"]} of {r["total"]} base controls"></div></div>'
        f'<div class="bar-val">{r["pct"]}% ({r["covered"]}/{r["total"]})</div></div>'
        for r in rows
    )
    bars = f"""
    <section><h2>Base-control coverage by platform</h2>{bar_rows}
    <div class="legend-note">Bars scaled to the highest platform ({max_pct}%).
    Coverage counts NIST 800-53r5 base controls referenced by active baseline checks.</div>
    </section>"""

    head = "".join(f"<th>{_esc(f)}</th>" for f in families)
    body_rows = []
    for code in sorted(grid):
        cells = "".join(
            f'<td class="heat" style="{_heat_style(grid[code].get(f, 0.0))}" '
            f'title="{_esc(code)} {_esc(f)}">{grid[code].get(f, 0.0)}%</td>'
            for f in families
        )
        body_rows.append(f'<tr><td class="rowhead">{_esc(code)}</td>{cells}</tr>')
    heatmap = f"""
    <section><h2>Coverage % by platform and NIST family</h2>
    <table><tr><th class="rowhead">Platform</th>{head}</tr>{''.join(body_rows)}</table>
    <div class="legend-note">Darker blue = higher coverage; every cell shows its value.</div>
    </section>"""

    missing_rows = "".join(
        f'<tr><td class="rowhead">{_esc(code)}</td>'
        f'<td style="text-align:left"><span class="chip nobaseline">NO BASELINE</span></td>'
        f'<td style="text-align:left">{_esc(", ".join(names) or "no candidates either")}</td></tr>'
        for code, names in sorted(result.missing_baseline.items())
    )
    missing = (
        f"""<section><h2>Platforms without a production baseline</h2>
        <table><tr><th class="rowhead">Platform</th><th>Status</th>
        <th>Vendor candidates available</th></tr>{missing_rows}</table></section>"""
        if result.missing_baseline
        else ""
    )

    if trend_points >= 2:
        trend = f"<section><h2>Enterprise coverage trend</h2>{trend_svg}</section>"
    else:
        trend = (
            "<section><h2>Enterprise coverage trend</h2>"
            f"<div class='legend-note'>Trend appears after two or more recorded "
            f"runs (currently {trend_points}).</div></section>"
        )

    stamp = time.strftime("%Y-%m-%d %H:%M")
    doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HTH Compliance Baseline Dashboard</title>
<style>{_CSS}</style></head>
<body><div class="viz-root">
<h1>HTH Compliance Baseline Dashboard</h1>
<div class="subtitle">Tenable .audit baseline posture vs NIST SP 800-53r5 &middot; generated {stamp}</div>
{tiles}{bars}{heatmap}{missing}{trend}
<footer>Generated by pysc. Coverage reflects audit-file content (checks referencing
NIST controls), not fleet scan pass rates.</footer>
</div></body></html>"""

    with open(output_file, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return output_file
