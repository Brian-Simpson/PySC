"""Per-run coverage history (SQLite) for trend reporting.

Schema:
  runs(run_id, ts, tool_version, git_sha, notes)
  coverage(run_id, platform, family, controls_total, controls_covered,
           controls_recoverable, checks_active, checks_inactive, pass_rate)
  control_state(run_id, platform, control_id, status, risk_score)

pass_rate stays NULL until the maturity workflow (Phase 5) supplies fleet
pass-rate exports.
"""

import sqlite3
import time
from collections import defaultdict
from pathlib import Path

from pysc import __version__
from pysc.nist.oscal import OscalCatalog

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
  run_id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  tool_version TEXT,
  git_sha TEXT,
  notes TEXT
);
CREATE TABLE IF NOT EXISTS coverage (
  run_id INTEGER REFERENCES runs(run_id),
  platform TEXT NOT NULL,
  family TEXT NOT NULL,
  controls_total INTEGER,
  controls_covered INTEGER,
  controls_recoverable INTEGER,
  checks_active INTEGER,
  checks_inactive INTEGER,
  pass_rate REAL,
  PRIMARY KEY (run_id, platform, family)
);
CREATE TABLE IF NOT EXISTS control_state (
  run_id INTEGER REFERENCES runs(run_id),
  platform TEXT NOT NULL,
  control_id TEXT NOT NULL,
  status TEXT CHECK(status IN ('covered', 'recoverable', 'missing')),
  risk_score REAL,
  PRIMARY KEY (run_id, platform, control_id)
);
"""


class HistoryStore:
    def __init__(self, db_path):
        self.db_path = Path(db_path)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def close(self):
        self.conn.close()

    def record_enterprise_run(self, result, notes="", git_sha=""):
        """Snapshot an EnterpriseGapResult; returns the run_id."""
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO runs (ts, tool_version, git_sha, notes) VALUES (?, ?, ?, ?)",
            (time.strftime("%Y-%m-%d %H:%M:%S"), __version__, git_sha, notes),
        )
        run_id = cur.lastrowid

        for platform, analysis in result.analyses.items():
            baseline_set = set(analysis.target_baseline.keys())
            by_family = defaultdict(lambda: {"total": 0, "covered": 0, "recoverable": 0})
            for control_id in baseline_set:
                family, _ = OscalCatalog.family_of(control_id)
                bucket = by_family[family]
                bucket["total"] += 1
                if control_id in analysis.baseline_covered_set:
                    bucket["covered"] += 1
                elif control_id in analysis.inactive_coverage_opportunities:
                    bucket["recoverable"] += 1

            checks_active = analysis.baseline.checks_parsed
            checks_inactive = len(analysis.baseline.inactive_checks)
            for family, bucket in sorted(by_family.items()):
                cur.execute(
                    "INSERT INTO coverage VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)",
                    (
                        run_id,
                        platform,
                        family,
                        bucket["total"],
                        bucket["covered"],
                        bucket["recoverable"],
                        checks_active,
                        checks_inactive,
                    ),
                )

            for control_id in sorted(baseline_set):
                if control_id in analysis.baseline_covered_set:
                    status = "covered"
                elif control_id in analysis.inactive_coverage_opportunities:
                    status = "recoverable"
                else:
                    status = "missing"
                cur.execute(
                    "INSERT INTO control_state VALUES (?, ?, ?, ?, NULL)",
                    (run_id, platform, control_id, status),
                )

        self.conn.commit()
        return run_id

    def platform_trend(self, platform=None):
        """[(run_id, ts, platform, covered, recoverable, total)] per run."""
        query = """
            SELECT c.run_id, r.ts, c.platform,
                   SUM(c.controls_covered), SUM(c.controls_recoverable),
                   SUM(c.controls_total)
            FROM coverage c JOIN runs r ON r.run_id = c.run_id
            {where}
            GROUP BY c.run_id, c.platform
            ORDER BY c.run_id, c.platform
        """
        if platform:
            cur = self.conn.execute(
                query.format(where="WHERE c.platform = ?"), (platform,)
            )
        else:
            cur = self.conn.execute(query.format(where=""))
        return cur.fetchall()

    def export_csv(self, output_path):
        import csv

        cur = self.conn.execute(
            """
            SELECT r.run_id, r.ts, c.platform, c.family, c.controls_total,
                   c.controls_covered, c.controls_recoverable,
                   c.checks_active, c.checks_inactive, c.pass_rate
            FROM coverage c JOIN runs r ON r.run_id = c.run_id
            ORDER BY r.run_id, c.platform, c.family
            """
        )
        with open(output_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(
                [
                    "run_id", "ts", "platform", "family", "controls_total",
                    "controls_covered", "controls_recoverable",
                    "checks_active", "checks_inactive", "pass_rate",
                ]
            )
            writer.writerows(cur.fetchall())
        return output_path
