#!/usr/bin/env python3
"""Count custom_item blocks in vendor audit files."""
import re
from pathlib import Path
from collections import defaultdict

AUDIT_DIR = Path("c:/PySC/Audits")

# Map vendor keywords to vendor names
VENDOR_MAP = {
    "f5": "f5",
    "big-ip": "f5",
    "palo alto": "paloalto",
    "paloalto": "paloalto",
    "pan-os": "paloalto",
    "cisco": "cisco",
    "ios": "cisco_ios",
    "nxos": "cisco_nxos",
    "asa": "cisco_asa",
}

def detect_vendor(filename: str, content: str) -> str:
    """Detect vendor from filename and content."""
    filename_lower = filename.lower()
    content_lower = content.lower()[:2000]  # Check first 2000 chars
    
    # Check filename
    for keyword, vendor in VENDOR_MAP.items():
        if keyword in filename_lower:
            if vendor == "cisco":
                # Distinguish between ios/nxos/asa
                if "ios" in filename_lower or "ios" in content_lower:
                    return "cisco_ios"
                if "nxos" in filename_lower or "nx-os" in content_lower:
                    return "cisco_nxos"
                if "asa" in filename_lower:
                    return "cisco_asa"
                return "cisco_ios"  # default
            return vendor
    
    return "windows/other"

# Count custom_item blocks in each file
vendor_counts = defaultdict(lambda: {"files": [], "total_blocks": 0})

for audit_file in sorted(AUDIT_DIR.glob("*.audit")):
    try:
        content = audit_file.read_text()
        vendor = detect_vendor(audit_file.name, content)
        
        # Count <custom_item> blocks
        blocks = len(re.findall(r'<custom_item>', content))
        
        vendor_counts[vendor]["files"].append({
            "name": audit_file.name,
            "blocks": blocks
        })
        vendor_counts[vendor]["total_blocks"] += blocks
        
    except Exception as e:
        print(f"Error reading {audit_file.name}: {e}")

# Print report
print("\n=== CONTROL COUNT REPORT ===\n")
for vendor in sorted(vendor_counts.keys()):
    data = vendor_counts[vendor]
    print(f"{vendor.upper()}:")
    print(f"  Total Files: {len(data['files'])}")
    print(f"  Total Controls: {data['total_blocks']}")
    for f in data["files"]:
        print(f"    - {f['name']}: {f['blocks']}")
    print()

print("\n=== SUMMARY ===")
total_files = sum(len(data["files"]) for data in vendor_counts.values())
total_controls = sum(data["total_blocks"] for data in vendor_counts.values())
print(f"Total files: {total_files}")
print(f"Total controls: {total_controls}")
