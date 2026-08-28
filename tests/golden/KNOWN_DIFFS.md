# Known intentional divergences from the legacy engine

None. The extracted engine (pysc/normalize/_core.py) is byte-identical to the
legacy engine (pysc/_legacy/all_audits.py) on every golden input.

Any future intentional divergence must be recorded here (what changed, why,
which golden files are affected) AND codified in tests/test_parity_normalize.py.
No undocumented diff may pass the suite.
