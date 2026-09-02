"""Self-contained HTML compliance dashboard.

One portable file (inline CSS, no external assets, no JS dependencies) suitable
for posting to SharePoint/intranet. Charts are pure HTML/SVG: a horizontal bar
list for per-platform coverage, a platform x NIST-family heatmap table with
visible values (doubles as the table view), and a coverage trend line from the
history DB. Colors follow the HTH (Hilltop Holdings) brand guideline palette:
each platform gets its own categorical color (anchored on the brand PMS 287
blue / Golden / PMS 1805 red hues, extended around the hue wheel) with the CIS
potential drawn as a darker shade of the same hue; the heatmap shades each
platform row with a sequential ramp of that platform's own color, and PMS 1805
red marks critical/priority state, with brand typography (Gill Sans MT
headings, Calluna/Calibri body). Mark colors are
OKLCH-snapped into the chart lightness band and both light/dark 9-slot fill
palettes pass the dataviz palette validator (adjacent CVD deltaE >= 7,
contrast >= 3:1; rows are directly labeled, the mandated relief for pairs in
the 6-8 floor band); dark mode via prefers-color-scheme.
"""

import html as _html
import time
from collections import defaultdict

from pysc.nist.oscal import OscalCatalog

# Per-platform series palette, one slot per bar row (cycled if rows exceed
# slots). Fixed order; slots 0/1/3 are the brand blue/Golden/red hues. Each
# slot: (light fill, light CIS shade, dark fill, dark CIS shade) - the CIS
# shade is the same hue 0.14-0.16 OKLCH L darker than the fill.
_SERIES = [
    ("#2151af", "#001f7c", "#3d70d1", "#1545a2"),  # brand PMS 287 blue
    ("#b17d3a", "#7f4f00", "#ba8744", "#8e5d12"),  # brand Golden
    ("#008168", "#00523c", "#159f85", "#00755d"),  # teal
    ("#a82131", "#720003", "#cb454c", "#9b0d26"),  # brand PMS 1805 red
    ("#4d9351", "#1a6323", "#60a563", "#357a3a"),  # green
    ("#644395", "#3a1463", "#8160b5", "#593888"),  # purple
    ("#8e8f31", "#5f5f00", "#97983c", "#6e6e00"),  # olive
    ("#8b397c", "#59024e", "#ab569b", "#7e2d70"),  # magenta
    ("#009399", "#006369", "#24a5ab", "#007a81"),  # cyan
]

# --- OKLCH helpers (module-local, used only to derive the heatmap ramps) ----

def _hex_to_lin(h):
    h = h.lstrip("#")
    srgb = [int(h[i:i + 2], 16) / 255 for i in (0, 2, 4)]
    return [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in srgb]


def _lin_to_hex(rgb):
    out = []
    for c in rgb:
        c = max(0.0, min(1.0, c))
        s = 12.92 * c if c <= 0.0031308 else 1.055 * c ** (1 / 2.4) - 0.055
        out.append(round(s * 255))
    return "#{:02x}{:02x}{:02x}".format(*out)


def _hex_to_oklch(h):
    import math

    r, g, b = _hex_to_lin(h)
    l = (0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b) ** (1 / 3)
    m = (0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b) ** (1 / 3)
    s = (0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b) ** (1 / 3)
    L = 0.2104542553 * l + 0.7936177850 * m - 0.0040720468 * s
    a = 1.9779984951 * l - 2.4285922050 * m + 0.4505937099 * s
    bb = 0.0259040371 * l + 0.7827717662 * m - 0.8086757660 * s
    return L, math.hypot(a, bb), math.degrees(math.atan2(bb, a)) % 360


def _oklch_to_hex(L, C, H):
    import math

    a = C * math.cos(math.radians(H))
    b = C * math.sin(math.radians(H))
    l_ = (L + 0.3963377774 * a + 0.2158037573 * b) ** 3
    m_ = (L - 0.1055613458 * a - 0.0638541728 * b) ** 3
    s_ = (L - 0.0894841775 * a - 1.2914855480 * b) ** 3
    return _lin_to_hex([
        4.0767416621 * l_ - 3.3077115913 * m_ + 0.2309699292 * s_,
        -1.2684380046 * l_ + 2.6097574011 * m_ - 0.3413193965 * s_,
        -0.0041960863 * l_ - 0.7034186147 * m_ + 1.7076147010 * s_,
    ])


def _contrast(h1, h2):
    def _lum(h):
        r, g, b = _hex_to_lin(h)
        return 0.2126 * r + 0.7152 * g + 0.0722 * b

    hi, lo = sorted((_lum(h1), _lum(h2)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def _ramp_from(fill_hex, steps=13):
    """Sequential ramp in the fill's hue: monotone OKLCH L 0.92 -> 0.32,
    chroma tapered at the light end; each step paired with its readable ink."""
    _L, C, H = _hex_to_oklch(fill_hex)
    ramp = []
    for i in range(steps):
        t = i / (steps - 1)
        step = _oklch_to_hex(0.92 - t * 0.60, C * (0.35 + 0.65 * t), H)
        ink = "#ffffff" if _contrast(step, "#ffffff") >= 4.5 else "#0b0b0b"
        ramp.append((step, ink))
    return ramp


# One heatmap ramp per platform slot, derived from the slot's light-mode fill
# so the heatmap rows match the bar-chart colors.
_PLATFORM_RAMPS = [_ramp_from(fill) for fill, _lc, _df, _dc in _SERIES]

_CSS = """
:root { color-scheme: light dark; }
body {
  margin: 0; padding: 24px;
  font-family: Calluna, "Calluna Light", Calibri, "Segoe UI", system-ui, sans-serif;
  background: #f9f9f7; color: #0b0b0b;
}
.viz-root {
  --surface-1: #fcfcfb; --text-primary: #0b0b0b; --text-secondary: #52514e;
  --muted: #898781; --grid: #e1e0d9; --baseline: #c3c2b7;
  --brand-navy: #00308c; --brand-gold: #a47b48;
  --series-1: #2051af; --cis: #a77431; --good: #0ca30c; --critical: #af2734; --serious: #de988d;
  --border: rgba(11,11,11,0.10);
}
@media (prefers-color-scheme: dark) {
  body { background: #0d0d0d; color: #ffffff; }
  .viz-root {
    --surface-1: #1a1a19; --text-primary: #ffffff; --text-secondary: #c3c2b7;
    --muted: #898781; --grid: #2c2c2a; --baseline: #383835;
    --brand-navy: #ffffff;
    --series-1: #4e82e5; --cis: #b68038; --critical: #d3595c; --border: rgba(255,255,255,0.10);
  }
}
h1, h2, .tile .value { font-family: "Gill Sans Nova", "Gill Sans MT", Calibri, "Segoe UI", sans-serif; }
h1 {
  font-size: 20px; margin: 0 0 4px; color: var(--brand-navy);
  padding-bottom: 6px; border-bottom: 3px solid var(--brand-gold);
}
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
.bar-row { display: grid; grid-template-columns: 90px 1fr 150px; gap: 8px; align-items: center; margin: 6px 0; font-size: 13px; }
.bar-track { background: transparent; border-left: 2px solid var(--baseline); height: 16px; position: relative; }
.bar-cis { position: absolute; left: 0; top: 0; background: var(--cis); height: 100%; border-radius: 0 4px 4px 0; min-width: 2px; }
.bar-fill { position: absolute; left: 0; top: 0; background: var(--series-1); height: 100%; border-radius: 0 4px 4px 0; min-width: 2px; }
.bar-val { color: var(--text-secondary); font-variant-numeric: tabular-nums; }
.swatch { display: inline-block; width: 10px; height: 10px; border-radius: 2px; vertical-align: middle; margin-right: 3px; }
table { border-collapse: collapse; font-size: 12px; width: 100%; }
th, td { padding: 5px 8px; text-align: right; border: 1px solid var(--grid); }
th { color: var(--text-secondary); font-weight: 600; }
td.rowhead, th.rowhead { text-align: left; font-weight: 600; }
td.heat { font-variant-numeric: tabular-nums; }
.chip { display: inline-block; padding: 1px 8px; border-radius: 10px; font-size: 11px; font-weight: 600; }
.chip.missing { border: 1px solid var(--critical); color: var(--critical); }
.prio-score { font-weight: 700; font-variant-numeric: tabular-nums; white-space: nowrap; }
.prio-high { color: var(--critical); }
.legend-note { color: var(--muted); font-size: 11px; margin-top: 8px; }
svg text { fill: var(--text-secondary); font-size: 11px; }
footer { color: var(--muted); font-size: 11px; margin-top: 12px; }
"""

# Per-platform bar colors: .p<i> rows override the --series-1/--cis fallbacks.
_CSS += "".join(
    f".p{i} .bar-fill {{ background: {lf}; }} .p{i} .bar-cis {{ background: {lc}; }}\n"
    f".p{i} .swatch-fill {{ background: {lf}; }} .p{i} .swatch-cis {{ background: {lc}; }}\n"
    for i, (lf, lc, _df, _dc) in enumerate(_SERIES)
)
_CSS += "@media (prefers-color-scheme: dark) {\n" + "".join(
    f".p{i} .bar-fill {{ background: {df}; }} .p{i} .bar-cis {{ background: {dc}; }}\n"
    f".p{i} .swatch-fill {{ background: {df}; }} .p{i} .swatch-cis {{ background: {dc}; }}\n"
    for i, (_lf, _lc, df, dc) in enumerate(_SERIES)
) + "}\n"


def _esc(value):
    return _html.escape(str(value))


def _pct(part, whole):
    return round((part / whole) * 100, 2) if whole else 0.0


def _heat_style(pct, ramp, scale_max=100.0):
    """Sequential ramp cell: light ink on dark steps, dark ink on light steps.

    Shading is scaled to scale_max (the highest cell in the grid) so the ramp
    differentiates cells even while absolute coverage is low; every cell
    prints its absolute value, so the scaling is presentational only.
    """
    frac = (pct / scale_max) if scale_max else 0.0
    idx = min(int(frac * (len(ramp) - 1)), len(ramp) - 1)
    color, ink = ramp[idx]
    return f"background:{color};color:{ink}"


def _platform_rows(result):
    rows = []
    for code, analysis in sorted(result.analyses.items()):
        total = len(analysis.target_baseline)
        # CIS potential: base controls any file (baseline + CIS/DISA candidates)
        # can cover - the highest achievable coverage if candidate checks are
        # imported. Mirrors "Highest Potential" in Platform_Family_Coverage.
        cis = len(set(analysis.target_baseline) & analysis.all_possible_controls)
        rows.append(
            {
                "code": code,
                "baseline": analysis.baseline.short_name,
                "active": analysis.baseline.checks_parsed,
                "inactive": len(analysis.baseline.inactive_checks),
                "covered": analysis.baseline_coverage_count,
                "total": total,
                "pct": _pct(analysis.baseline_coverage_count, total),
                "cis": cis,
                "cis_pct": _pct(cis, total),
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
    """Overall enterprise coverage % per run as a single series line."""
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


def build_dashboard(result, output_file, history=None, attack_mappings=None):
    from pysc.report.priority import PRIORITY_FAMILIES, priority_gap_rows

    rows = _platform_rows(result)
    families, grid = _family_grid(result)
    priorities = priority_gap_rows(result)

    covered_sum = sum(r["covered"] for r in rows)
    total_sum = sum(r["total"] for r in rows)
    recoverable_sum = sum(r["recoverable"] for r in rows)
    additional_sum = sum(r["additional"] for r in rows)
    priority_family_gaps = sum(1 for p in priorities if p["family"] in PRIORITY_FAMILIES)

    tiles = f"""
    <section><div class="tiles">
      <div class="tile"><div class="value">{len(rows)}</div>
        <div class="label">Platforms under baseline management</div></div>
      <div class="tile"><div class="value">{_pct(covered_sum, total_sum)}%</div>
        <div class="label">Base-control coverage (all platforms)</div></div>
      <div class="tile"><div class="value">{priority_family_gaps}</div>
        <div class="label">Gaps in priority families (AC IA AU SC SI)</div></div>
      <div class="tile"><div class="value">{recoverable_sum}</div>
        <div class="label">Recoverable now (un-comment existing checks)</div></div>
      <div class="tile"><div class="value">{additional_sum}</div>
        <div class="label">Require new checks (import from benchmarks)</div></div>
    </div></section>"""

    max_pct = max((max(r["pct"], r["cis_pct"]) for r in rows), default=1) or 1
    bar_rows = "".join(
        f'<div class="bar-row p{i % len(_SERIES)}"><div>{_esc(r["code"])}</div>'
        f'<div class="bar-track">'
        f'<div class="bar-cis" style="width:{max(r["cis_pct"] / max_pct * 100, 0.5)}%" '
        f'title="{_esc(r["code"])} CIS potential: {r["cis"]} of {r["total"]} base controls"></div>'
        f'<div class="bar-fill" style="width:{max(r["pct"] / max_pct * 100, 0.5)}%" '
        f'title="{_esc(r["code"])} HTH baseline: {r["covered"]} of {r["total"]} base controls"></div>'
        f'</div>'
        f'<div class="bar-val">{r["pct"]}% / {r["cis_pct"]}% CIS</div></div>'
        for i, r in enumerate(rows)
    )
    bars = f"""
    <section><h2>Base-control coverage by platform</h2>{bar_rows}
    <div class="legend-note"><span class="p0">
    <span class="swatch swatch-fill"></span></span>Solid = HTH baseline coverage &nbsp;
    <span class="p0"><span class="swatch swatch-cis"></span></span>Darker shade of the same
    color = CIS benchmark potential (highest achievable if candidate checks are imported).
    Each platform has its own color. Bars scaled to the highest platform potential ({max_pct}%).
    Coverage counts NIST 800-53r5 base controls referenced by active baseline checks.</div>
    </section>"""

    head = "".join(f"<th>{_esc(f)}</th>" for f in families)
    grid_max = max(
        (pct for cells in grid.values() for pct in cells.values()), default=0.0
    )
    body_rows = []
    for i, code in enumerate(sorted(grid)):
        ramp = _PLATFORM_RAMPS[i % len(_PLATFORM_RAMPS)]
        cells = "".join(
            f'<td class="heat" style="{_heat_style(grid[code].get(f, 0.0), ramp, grid_max)}" '
            f'title="{_esc(code)} {_esc(f)}">{grid[code].get(f, 0.0)}%</td>'
            for f in families
        )
        body_rows.append(f'<tr><td class="rowhead">{_esc(code)}</td>{cells}</tr>')
    heatmap = f"""
    <section><h2>Coverage % by platform and NIST family</h2>
    <table><tr><th class="rowhead">Platform</th>{head}</tr>{''.join(body_rows)}</table>
    <div class="legend-note">Each row is shaded in its platform's color (same colors as the
    coverage bars); darker = higher coverage. Shading scaled to the highest cell
    ({grid_max}%), every cell shows its absolute value.</div>
    </section>"""

    # Top remediation priorities: what to address first, ranked.
    top = priorities[:15]
    prio_rows_html = "".join(
        '<tr><td class="prio-score">'
        + ('<span class="prio-high">HIGH</span>' if p["score"] >= 3 else "STD")
        + f' {p["score"]}</td>'
        f'<td class="rowhead">{_esc(p["platform"])}</td>'
        f'<td style="text-align:left">{_esc(p["control_id"])}</td>'
        f'<td style="text-align:left">{_esc(p["title"])}</td>'
        f'<td style="text-align:left">{_esc(p["family_name"])}</td>'
        f'<td style="text-align:left">{_esc(p["action"])}</td></tr>'
        for p in top
    )
    priorities_section = f"""
    <section><h2>Top remediation priorities</h2>
    <table><tr><th>Priority</th><th class="rowhead">Platform</th><th style="text-align:left">Control</th>
    <th style="text-align:left">Title</th><th style="text-align:left">NIST Family</th>
    <th style="text-align:left">Action</th></tr>{prio_rows_html}</table>
    <div class="legend-note">Ranked by NIST family criticality (AC/IA/AU/SC/SI weigh 3x)
    and effort (missing checks outrank recoverable ones). Showing top {len(top)} of
    {len(priorities)} open gaps; the full ranked list is the Priority_Gaps sheet of the
    Unified_Compliance_Matrix workbook.</div>
    </section>"""

    # Common attack vectors exposed by the current gaps (ATT&CK mitigations
    # weakened by open controls) - replaces the low-signal coverage trend.
    vectors_section = ""
    if attack_mappings:
        from pysc.nist.attack import attack_vectors_for_gaps

        vectors = attack_vectors_for_gaps(result, attack_mappings, limit=10)
        vector_rows_html = "".join(
            f'<tr><td style="text-align:left">{_esc(v["technique_id"])}</td>'
            f'<td style="text-align:left">{_esc(v["technique_name"])}'
            + (
                f' <span class="legend-note">(+{v["sub_technique_count"]} sub-techniques)</span>'
                if v["sub_technique_count"]
                else ""
            )
            + f'</td><td style="text-align:left">{_esc(", ".join(v["controls"][:6]))}'
            + ("…" if len(v["controls"]) > 6 else "")
            + f'</td><td style="text-align:left">{_esc(", ".join(v["platforms"]))}</td></tr>'
            for v in vectors
        )
        vectors_section = f"""
    <section><h2>Common attack vectors exposed by current gaps</h2>
    <table><tr><th style="text-align:left">Technique</th><th style="text-align:left">Attack Vector</th>
    <th style="text-align:left">Weakened Mitigations (open gap controls)</th>
    <th style="text-align:left">Platforms Affected</th></tr>{vector_rows_html}</table>
    <div class="legend-note">MITRE ATT&amp;CK techniques whose NIST 800-53r5 mitigating
    controls are open gaps (CTID mappings). Closing the listed controls restores
    mitigation coverage for the vector; ranked by platform breadth, then by number
    of weakened controls.</div>
    </section>"""

    stamp = time.strftime("%Y-%m-%d %H:%M")
    doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HTH Compliance Baseline Dashboard</title>
<style>{_CSS}</style></head>
<body><div class="viz-root">
<h1>HTH Compliance Baseline Dashboard</h1>
<div class="subtitle">Tenable .audit baseline posture vs NIST SP 800-53r5 &middot; generated {stamp}</div>
{tiles}{bars}{priorities_section}{vectors_section}{heatmap}
<footer>Generated by pysc. Coverage reflects audit-file content (checks referencing
NIST controls), not fleet scan pass rates.</footer>
</div></body></html>"""

    with open(output_file, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return output_file
