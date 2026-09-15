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

    def __init__(self, cis_benchmark_path, audit_type='PAFW'):
        self.cis_benchmark_path = cis_benchmark_path
        self.audit_type = audit_type
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
        """Load used controls from Excel for this audit type"""
        if not HAS_OPENPYXL:
            print("⚠️  openpyxl not installed, skipping controls validation", file=sys.stderr)
            return False

        try:
            wb = openpyxl.load_workbook(catalog_path)
            # For platform-specific catalogs, use the audit type as sheet name
            # But also support All_Occurrences for backwards compat
            sheet_name = self.audit_type if self.audit_type in wb.sheetnames else 'All_Occurrences'

            if sheet_name not in wb.sheetnames:
                print(f"⚠️  Neither '{self.audit_type}' nor 'All_Occurrences' sheet found", file=sys.stderr)
                return False

            ws = wb[sheet_name]
            for row in ws.iter_rows(values_only=True):
                if row and row[0]:
                    self.used_controls.add(str(row[0]).strip())

            print(f"✅ Loaded {len(self.used_controls)} controls from '{sheet_name}' sheet", file=sys.stderr)
            return True
        except Exception as e:
            print(f"⚠️  Controls load: {e}", file=sys.stderr)
            return False

    def is_control_used(self, description):
        """Check if control is used by ID matching"""
        if not self.used_controls:
            return True  # If no baseline loaded, keep all controls

        # Extract ID from description (e.g., "1.0000" from "1.0000 - PAFW - ...")
        id_match = re.match(r'(\d+\.\d+)', description)
        if not id_match:
            return False

        control_id = id_match.group(1)
        return control_id in self.used_controls

    def load_baseline_controls(self, baseline_path):
        """Load control IDs from the baseline file"""
        self.used_controls.clear()
        try:
            with open(baseline_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            items = re.findall(r'<custom_item>.*?</custom_item>', content, re.DOTALL)
            for item in items:
                item_obj = AuditItem(item)
                if item_obj.description:
                    # Extract just the ID (e.g., "1.0000" from "1.0000 - PAFW - ...")
                    id_match = re.match(r'(\d+\.\d+)', item_obj.description)
                    if id_match:
                        self.used_controls.add(id_match.group(1))
            print(f"✅ Loaded {len(self.used_controls)} control IDs from baseline", file=sys.stderr)
            return True
        except Exception as e:
            print(f"⚠️  Baseline load: {e}", file=sys.stderr)
            return False

    def comment_out_control(self, item_content):
        """Completely comment out a control - EVERY line including tags"""
        lines = item_content.split('\n')
        commented = []

        for line in lines:
            if not line.strip():
                # Keep blank lines as-is
                commented.append(line)
            else:
                # Add # prefix to every non-blank line that isn't already commented
                if not line.lstrip().startswith('#'):
                    commented.append('#' + line)
                else:
                    commented.append(line)

        return '\n'.join(commented)

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

            commented_count = 0
            used_count = 0

            for item_str in items:
                item = AuditItem(item_str)
                is_used = self.is_control_used(item.description)

                if is_used:
                    fixed = self.fix_xsl_statement(item)
                    used_count += 1
                else:
                    fixed = self.comment_out_control(item_str)
                    commented_count += 1

                key = item.get_unique_key()
                if key not in self.consolidated_items:
                    self.consolidated_items[key] = fixed

            if used_count > 0 or commented_count > 0:
                print(f"✅ Processed: {used_count} used, {commented_count} commented", file=sys.stderr)
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

def extract_controls_to_sheet(consolidated_items, output_audit_path, catalog_path, audit_type):
    """Extract controls from consolidated audit and populate Excel sheet"""
    if not HAS_OPENPYXL:
        return

    try:
        # Read consolidated audit to extract control details
        with open(output_audit_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        items = re.findall(r'<custom_item>.*?</custom_item>', content, re.DOTALL)
        rows = []

        for item_str in items:
            # Skip commented out items
            if item_str.strip().startswith('#'):
                continue

            item = AuditItem(item_str)
            desc = item.description

            # Extract key fields
            row_dict = {
                'control_type': 'AUDIT_XML',
                'control_key': desc[:50] if desc else 'Unknown',
                'control_keyword': desc[:50] if desc else 'Unknown',
                'expected_value': '',
                'description': desc,
                'info': '',
                'reference': '',
                'condition_type': 'AND',
                'report_type': None,
                'report_description': None,
                'raw_fields': item_str[:200],
                'source_count': '1',
                'source_files': '',
                'source_file': '',
                'type': 'AUDIT_XML',
                'api_request_type': item.api_request_type,
                'xsl_stmt': item.xsl_stmts[0] if item.xsl_stmts else '',
                'regex': '.*',
                'request': '',
            }
            rows.append(row_dict)

        if not rows:
            return

        # Update Excel sheet
        wb = openpyxl.load_workbook(catalog_path)

        # Use standard columns (consistent across all sheets)
        columns = [
            'control_type', 'control_key', 'control_keyword', 'expected_value',
            'description', 'info', 'reference', 'condition_type', 'report_type',
            'report_description', 'raw_fields', 'source_count', 'source_files',
            'source_file', 'Custom item', 'Conditional', 'type', 'solution', 'see_also',
            'value_type', 'value_data', 'reg_key', 'reg_item', 'reg_option', 'expect',
            'api_request_type', 'request', 'xsl_stmt', 'regex', 'item', 'cmd', 'right_type',
            'not_expect', 'audit_policy_subcategory', 'check_type', 'sql_request', 'sql_types',
            'sql_expect', 'rpm', 'operator', 'severity', 'password_policy', 'reg_include_hku_users',
            'min_occurrences', 'f5_command', 'json_transform', 'powershell_args', 'string_required',
            'match_all', 'mask', 'lockout_policy', 'account_type', 'key_item', 'wmi_namespace',
            'wmi_request', 'wmi_attribute', 'wmi_key', 'file_required', 'timeout', 'is_substring',
            'where', 'dont_echo_cmd', 'interface_name', 'only_show_cmd_output', 'policy_arn',
            'powershell_option', 'reg_ignore_hku_users', 'reg_type', 'shared_key', 'show_output',
            'system', 'tmsh'
        ]

        # Remove old sheet if it exists
        if audit_type in wb.sheetnames:
            del wb[audit_type]

        # Create new sheet
        ws = wb.create_sheet(audit_type)

        # Write header row
        ws.append(columns)

        # Write data rows
        for row_dict in rows:
            row_values = []
            for col in columns:
                row_values.append(row_dict.get(col))
            ws.append(row_values)

        wb.save(catalog_path)
        print(f"✅ Updated {audit_type} sheet: {len(rows)} controls", file=sys.stderr)
    except Exception as e:
        print(f"⚠️  Excel update: {e}", file=sys.stderr)

def main():
    if len(sys.argv) < 5:
        print("Usage: python audit_consolidator.py PAFW input.audit cis.audit output.audit [baseline.audit] [controls.xlsx]")
        sys.exit(1)

    audit_type = sys.argv[1]
    input_audit = Path(sys.argv[2])
    cis_benchmark = Path(sys.argv[3])
    output_file = Path(sys.argv[4])
    baseline_audit = Path(sys.argv[5]) if len(sys.argv) > 5 else None
    controls_catalog = Path(sys.argv[6]) if len(sys.argv) > 6 else None

    if not input_audit.exists() or not cis_benchmark.exists():
        print(f"❌ Files not found", file=sys.stderr)
        sys.exit(1)

    consolidator = AuditConsolidator(str(cis_benchmark), audit_type=audit_type)

    # Load baseline controls if provided (to uncomment matching controls)
    if baseline_audit and baseline_audit.exists():
        consolidator.load_baseline_controls(str(baseline_audit))
    # Otherwise, load controls catalog if provided
    elif controls_catalog and controls_catalog.exists():
        consolidator.load_controls_catalog(str(controls_catalog))

    header = consolidator.consolidate(str(input_audit))
    if header:
        consolidator.write_consolidated(output_file, header)

        # Populate Excel sheet with extracted controls
        if controls_catalog and controls_catalog.exists():
            extract_controls_to_sheet(consolidator.consolidated_items, str(output_file), str(controls_catalog), audit_type)
    else:
        print(f"❌ Failed to consolidate", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
