Catalog Controls Script
=======================

This folder contains `catalog_controls.py` — a utility to scan `.audit` files and produce an Excel workbook cataloging controls.

Quick start:

1. Activate your Python environment (use your project's venv).
2. Install dependency:

```bash
pip install openpyxl
```

1. Run the script:

```bash
python tools/catalog_controls.py --input "c:\PySC\audit_inputs" --output controls_catalog.xlsx
```

Output:

- `controls_catalog.xlsx` with one sheet per detected platform code (e.g. MSSRV, MSWRK, PAFW, NXOS, IOS, UNKNOWN).
