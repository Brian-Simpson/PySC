#!/usr/bin/env python3
"""
Audit Consolidator - Post-processor for TAP audit files
Fixes broken XSL, consolidates audits, deduplicates, comments out unused controls, and validates

Usage: python audit_consolidator.py PAFW input.audit cis.audit output.audit [controls.xlsx]
"""

import sys
import re
import subprocess
from pathlib import Path
from collections import OrderedDict

try:
    import openpyxl
    HAS_OPENPYXL = True
except ImportError:
    HAS_OPENPYXL = False

class AuditItem:
    """Represents a single audit custom_item"""
    def __init__(self, content):
        self.content = content
        self.description = self._extract_field('description')
        self.api_request_type = self._extract_field('api_request_type')
        self.xsl_stmts = self._extract_xsl_statements()

    def _extract_field(self, field_name):
        pattern = rf'{field_name}\s*:\s*"([^"]*)"'
        match = re.search(pattern, self.content)
        return match.group(1) if match else ""

    def _extract_xsl_statements(self):
        pattern = r'xsl_stmt\s*:\s*"([^"]*)"'
        return re.findall(pattern, self.content)

    def has_broken_xsl(self):
        for stmt in self.xsl_stmts:
            if stmt.startswith('</') and not any(opening in stmt for opening in ['<xsl:template', '<xsl:for-each', '<xsl:choose']):
                return True
        return False

    def get_unique_key(self):
        return self.description

class AuditConsolidator:
    """Consolidates and fixes audit files"""

    def __init__(self, cis_benchmark_path):
        self.cis_patterns = self._load_cis_patterns(cis_benchmark_path)
        self.consolidated_items = OrderedDict()
        self.used_controls = set()

    def _load_cis_patterns(self, cis_path):
        patterns = {}
        try:
            with open(cis_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            items = re.findall(r'<custom_item>.*?</custom_item>', content, re.DOTALL)
            for item in items:
                api_type = re.search(r'api_request_type\s*:\s*"([^"]*)"', item)
                xsl_stmts = re.findall(r'xsl_stmt\s*:\s*"([^"]*)"', item)
                if api_type and xsl_stmts:
                    key = api_type.group(1)
                    if key not in patterns:
                        patterns[key] = xsl_stmts
        except Exception as e:
            print(f"⚠️  CIS patterns: {e}", file=sys.stderr)
        return patterns

    def load_controls_catalog(self, catalog_path):
        """Load used controls from Excel"""
        if not HAS_OPENPYXL:
            print("⚠️  openpyxl not installed, skipping controls validation", file=sys.stderr)
            return False

        try:
            wb = openpyxl.load_workbook(catalog_path)
            if 'All_Occurrences' not in wb.sheetnames:
                print(f"⚠️  'All_Occurrences' sheet not found", file=sys.stderr)
                return False

            ws = wb['All_Occurrences']
            for row in ws.iter_rows(values_only=True):
                if row and row[0]:
                    self.used_controls.add(str(row[0]).strip())

            print(f"✅ Loaded {len(self.used_controls)} controls", file=sys.stderr)
            return True
        except Exception as e:
            print(f"⚠️  Controls load: {e}", file=sys.stderr)
            return False

    def is_control_used(self, description):
        """Check if control is used"""
        if not self.used_controls:
            return True
        for used in self.used_controls:
            if used.lower() in description.lower():
                return True
        return False

    def comment_out_control(self, item_content):
        """Completely comment out a control - EVERY line including tags"""
        lines = item_content.split('\n')
        commented = []

        for line in lines:
            if not line.strip():
                # Keep blank lines
                commented.append(line)
            elif line.strip().startswith('#'):
                # Already commented, keep as-is
                commented.append(line)
            else:
                # Add # to the BEGINNING of the line (before any whitespace)
                # This ensures tags and all content get commented
                commented.append('#' + line)

        result = '\n'.join(commented)
        return result

    def fix_xsl_statement(self, item):
        """Fix broken XSL"""
        if not item.has_broken_xsl():
            return item.content

        api_type = item.api_request_type
        if api_type not in self.cis_patterns:
            return item.content

        proper_xsl = self.cis_patterns[api_type]
        fixed = re.sub(r'xsl_stmt\s*:.*\n?', '', item.content)
        insert_point = fixed.rfind('</custom_item>')
        xsl_lines = '\n  '.join([f'xsl_stmt         : "{stmt}"' for stmt in proper_xsl])
        return fixed[:insert_point] + '  ' + xsl_lines + '\n' + fixed[insert_point:]

    def consolidate(self, audit_path):
        """Consolidate audit file"""
        try:
            with open(audit_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            header_match = re.search(r'^.*?(<check_type[^>]*>)', content, re.DOTALL)
            header = header_match.group(1) if header_match else '<check_type:"Palo_Alto">'

            items = re.findall(r'<custom_item>.*?</custom_item>', content, re.DOTALL)

            # Replace version checks with single generic check
            items = self._simplify_device_checks(items)

            for item_str in items:
                item = AuditItem(item_str)
                is_used = self.is_control_used(item.description)

                if is_used:
                    fixed = self.fix_xsl_statement(item)
                else:
                    fixed = self.comment_out_control(item_str)

                if item.get_unique_key() not in self.consolidated_items:
                    self.consolidated_items[item.get_unique_key()] = fixed

            return header
        except Exception as e:
            print(f"❌ Consolidate: {e}", file=sys.stderr)
            return None

    def _simplify_device_checks(self, items):
        """Replace multiple version checks with single generic check"""
        version_patterns = [
            'Check for Palo Alto version',
            'Panorama model',
            'Panorama system-mode'
        ]

        # Check if we have version checks
        has_version_checks = any(
            any(pattern in item for pattern in version_patterns)
            for item in items
        )

        if not has_version_checks:
            return items

        # Filter out version checks
        filtered_items = [
            item for item in items
            if not any(pattern in item for pattern in version_patterns)
        ]

        # Create single generic device check
        generic_check = '''<custom_item>
      type             : AUDIT_XML
      description      : "Device Type Check - Palo Alto Firewall"
      info             : "Verify this is a Palo Alto Firewall device."
      solution         : "Ensure this audit is run against a Palo Alto Firewall."
      reference        : ""
      see_also         : "See HTH Policies and Standards"
      expect           : ".*"
      api_request_type : "op"
      request          : "<show><system><info></info></system></show>"
      xsl_stmt         : "<xsl:value-of select="/response/result/system/sw-version"/>"
      regex            : ".*"
    </custom_item>'''

        return [generic_check] + filtered_items

    def write_consolidated(self, output_path, header):
        """Write output"""
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write('# Consolidated audit - auto-generated\n')
                f.write(header + '\n\n')
                for item in self.consolidated_items.values():
                    f.write(item + '\n\n')
                f.write('</check_type>\n')

            print(f"✅ Consolidated: {output_path}")
            print(f"   Items: {len(self.consolidated_items)}")
            return True
        except Exception as e:
            print(f"❌ Write: {e}", file=sys.stderr)
            return False

def main():
    if len(sys.argv) < 5:
        print("Usage: python audit_consolidator.py PAFW input.audit cis.audit output.audit [controls.xlsx]")
        sys.exit(1)

    audit_type = sys.argv[1]
    input_audit = Path(sys.argv[2])
    cis_benchmark = Path(sys.argv[3])
    output_file = Path(sys.argv[4])
    controls_catalog = Path(sys.argv[5]) if len(sys.argv) > 5 else None

    if not input_audit.exists() or not cis_benchmark.exists():
        print(f"❌ Files not found", file=sys.stderr)
        sys.exit(1)

    consolidator = AuditConsolidator(str(cis_benchmark))

    # Load controls catalog if provided
    if controls_catalog and controls_catalog.exists():
        consolidator.load_controls_catalog(str(controls_catalog))

    header = consolidator.consolidate(str(input_audit))
    if header:
        consolidator.write_consolidated(output_file, header)
    else:
        print(f"❌ Failed to consolidate", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
