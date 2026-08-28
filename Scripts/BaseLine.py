import argparse
import json
import logging
import re
import requests
from pathlib import Path
from typing import Dict, List
from concurrent.futures import ThreadPoolExecutor

import pandas as pd

# -------------------------
# Logging
# -------------------------
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

# -------------------------
# Regex
# -------------------------
CUSTOM_BLOCK_PATTERN = re.compile(r'<custom_item>([\s\S]*?)</custom_item>', re.IGNORECASE)
KEY_VALUE_PATTERN = re.compile(r'^\s*([A-Za-z0-9_-]+)\s*:\s*(.*)')
INDEX_PATTERN = re.compile(r'\b(\d+)\b')

# -------------------------
# Cache
# -------------------------
CACHE_FILE = Path("nist_cache.json")

def load_cache():
    return json.loads(CACHE_FILE.read_text()) if CACHE_FILE.exists() else {}

def save_cache(cache):
    CACHE_FILE.write_text(json.dumps(cache, indent=2))

NIST_CACHE = load_cache()

# -------------------------
# NIST Mapping
# -------------------------
def infer_nist_control(audit_key: str) -> str:
    k = audit_key.lower()

    if "password" in k:
        return "IA-5(1)"
    if "lockout" in k:
        return "AC-7"
    if audit_key.startswith("Se"):
        return "AC-6"
    if "log" in k:
        return "AU-4"
    if "policy" in k:
        return "CM-6"
    if "defender" in k:
        return "SI-3"
    if "behavior" in k:
        return "SI-4"

    return ""

def lookup_nist_api(audit_key: str) -> str:
    if audit_key in NIST_CACHE:
        return NIST_CACHE[audit_key]

    result = infer_nist_control(audit_key)

    try:
        requests.get(
            "https://services.nvd.nist.gov/rest/json/cpes/2.0",
            params={"keywordSearch": audit_key},
            timeout=5
        )
    except Exception:
        pass

    NIST_CACHE[audit_key] = result
    save_cache(NIST_CACHE)

    return result

# -------------------------
# Helpers
# -------------------------
def normalize_audit_key(key: str, text: str) -> str:
    t = text.lower()

    if key == "Retention":
        if "application" in t:
            return "ApplicationLogRetention"
        if "security" in t:
            return "SecurityLogRetention"
        if "system" in t:
            return "SystemLogRetention"

    return key

def batch_lookup_nist(keys):
    with ThreadPoolExecutor(max_workers=10) as ex:
        return dict(ex.map(lambda k: (k, lookup_nist_api(k)), keys))

def get_control_family(n):
    return n.split("-")[0] if n else ""

def get_control_family_name(f):
    return {
        "AC": "Access Control",
        "AU": "Audit and Accountability",
        "IA": "Identification",
        "SI": "System Integrity",
        "CM": "Configuration Management"
    }.get(f, "")

def extract_cis(attrs):
    ref = attrs.get("reference", "")
    return ref.split("|")[0].strip() if "|" in ref else ""
def load_file(path: Path) -> str:
    return path.read_text(errors="ignore")

def parse_block(block: str) -> Dict[str, str]:
    attrs = {}
    for line in block.splitlines():
        m = KEY_VALUE_PATTERN.match(line.strip())
        if m:
            attrs[m.group(1).lower()] = m.group(2)
    return attrs

def extract_index(desc: str):
    m = INDEX_PATTERN.search(desc)
    return m.group(1) if m else "N/A"

def calc_key(attrs, desc):
    text = " ".join(attrs.values())

    m = re.search(r"Properties\['(.+?)'\]", text)
    if m:
        return m.group(1)

    if "Get-NetIPConfiguration" in text:
        return "NetIPConfiguration"

    return "UNKNOWN"

def classify(key, text):
    if key.startswith("Se"):
        return "USER_RIGHTS"
    if "auditpol" in text.lower():
        return "AuditPolicy"
    if "Get-ItemProperty" in text:
        return "Registry"
    return "Other"

def process(text: str):
    data = []
    matches = list(CUSTOM_BLOCK_PATTERN.finditer(text))

    keys = []
    blocks = []

    for m in matches:
        attrs = parse_block(m.group(1))
        if not attrs:
            continue

        desc = attrs.get("description", "")
        key = normalize_audit_key(calc_key(attrs, desc), str(attrs))

        keys.append(key)
        blocks.append((attrs, desc, key))

    nist_map = batch_lookup_nist(set(keys))

    for i, (attrs, desc, key) in enumerate(blocks, 1):
        if i % 10 == 0:
            print(f"{i}/{len(blocks)}")

        nist = nist_map.get(key, "")
        fam = get_control_family(nist)

        data.append({
            "index_id": extract_index(desc),
            "audit_key": key,
            "category": classify(key, str(attrs)),
            "cis": extract_cis(attrs),
            "nist": nist,
            "family": fam,
            "family_name": get_control_family_name(fam)
        })

    return data

def baseline(data):
    return list({r["audit_key"]: r for r in data}.values())

def export(data, path):
    with pd.ExcelWriter(path, engine="openpyxl") as w:
        pd.DataFrame(data).to_excel(w, "Indexed", index=False)
        pd.DataFrame(baseline(data)).to_excel(w, "Baseline Controls", index=False)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("files", nargs="*")
    args = parser.parse_args()

    if not args.files:
        args.files = [input("Enter audit file path: ").strip()]

    for f in args.files:
        path = Path(f)

        if not path.exists():
            print("File not found:", f)
            continue

        print("Processing:", f)

        data = process(load_file(path))
        export(data, path.with_suffix(".xlsx"))

        print("Done:", f)

if __name__ == "__main__":
    main()