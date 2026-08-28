"""Vendored legacy engine (verbatim copies; do not edit).

- all_audits.py: byte-for-byte copy of C:\\PySC\\ALL_AUDITS.py, the canonical
  normalizer/gap pipeline. Serves as the parity oracle while the pysc package
  extracts its functionality. Import via pysc.config.load_legacy(), which sets
  the PYSC_* env vars first and re-points SCRIPT_DIR at the workspace root.
- pysc_block_parser.py: copy of Scripts\\pysc_block_parser.py.
"""
