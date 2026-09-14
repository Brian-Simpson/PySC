#!/usr/bin/env python3
"""
Audit Consolidator - Post-processor for TAP audit files
Fixes broken XSL statements, consolidates audit items, and deduplicates

Usage: python audit_consolidator.py <audit_type> <input_audit> <cis_benchmark> <output_file>
Example: python audit_consolidator.py PAFW PAFW_0002.audit CIS_benchmark.audit consolidated.audit
"""

import sys
import re
from pathlib import Path
from collections import OrderedDict

class AuditItem:
    """Represents a single audit custom_item"""
    def __init__(self, content):
        self.content = content
        self.description = self._extract_field('description')
        self.api_request_type = self._extract_field('api_request_type')
        self.xsl_stmts = self._extract_xsl_statements()

    def _extract_field(self, field_name):
        """Extract a field value from the item"""
        pattern = rf'{field_name}\s*:\s*"([^"]*)"'
        match = re.search(pattern, self.content)
        return match.group(1) if match else ""

    def _extract_xsl_statements(self):
        """Extract all xsl_stmt lines"""
        pattern = r'xsl_stmt\s*:\s*"([^"]*)"'
        return re.findall(pattern, self.content)

    def has_broken_xsl(self):
        """Check if XSL statements are broken (orphaned closing tags)"""
        for stmt in self.xsl_stmts:
            if stmt.startswith('</') and not any(opening in stmt for opening in ['<xsl:template', '<xsl:for-each', '<xsl:choose']):
                return True
        return False

    def get_unique_key(self):
        """Get a unique key for deduplication"""
        return self.description

    def __repr__(self):
        return self.content

class AuditConsolidator:
    """Consolidates and fixes audit files"""

    def __init__(self, cis_benchmark_path):
        self.cis_patterns = self._load_cis_patterns(cis_benchmark_path)
        self.consolidated_items = OrderedDict()

    def _load_cis_patterns(self, cis_path):
        """Load XSL patterns from CIS benchmark file"""
        patterns = {}
        try:
            with open(cis_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Extract all custom_items
            items = re.findall(r'<custom_item>.*?</custom_item>', content, re.DOTALL)

            for item in items:
                api_type = re.search(r'api_request_type\s*:\s*"([^"]*)"', item)
                xsl_stmts = re.findall(r'xsl_stmt\s*:\s*"([^"]*)"', item)

                if api_type and xsl_stmts:
                    key = api_type.group(1)
                    if key not in patterns:
                        patterns[key] = xsl_stmts
        except Exception as e:
            print(f"Warning: Could not load CIS patterns: {e}", file=sys.stderr)

        return patterns

    def fix_xsl_statement(self, item, cis_patterns):
        """Fix broken XSL statements based on CIS patterns"""
        api_type = item.api_request_type

        if not item.has_broken_xsl():
            return item.content

        # Get appropriate XSL pattern for this API type
        if api_type in cis_patterns:
            proper_xsl = cis_patterns[api_type]
            fixed_content = item.content

            # Replace all xsl_stmt lines with proper ones
            fixed_content = re.sub(r'xsl_stmt\s*:.*', '', fixed_content)

            # Add proper XSL statements
            insert_point = fixed_content.rfind('</custom_item>')
            xsl_lines = '\n  '.join([f'xsl_stmt         : "{stmt}"' for stmt in proper_xsl])
            fixed_content = fixed_content[:insert_point] + '  ' + xsl_lines + '\n' + fixed_content[insert_point:]

            return fixed_content

        return item.content

    def consolidate(self, audit_file_path, cis_benchmark_path):
        """Consolidate and fix audit file"""
        try:
            with open(audit_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Extract header and all custom_items
            header_match = re.search(r'^.*?(<check_type[^>]*>)', content, re.DOTALL)
            header = header_match.group(1) if header_match else '<check_type:"Palo_Alto">'

            # Extract all custom_item blocks
            items = re.findall(r'<custom_item>.*?</custom_item>', content, re.DOTALL)

            # Process items
            for item_str in items:
                item = AuditItem(item_str)
                unique_key = item.get_unique_key()

                # Fix broken XSL
                if item.has_broken_xsl():
                    fixed_content = self.fix_xsl_statement(item, self.cis_patterns)
                else:
                    fixed_content = item_str

                # Deduplicate by description
                if unique_key not in self.consolidated_items:
                    self.consolidated_items[unique_key] = fixed_content

            return header

        except Exception as e:
            print(f"Error consolidating audit file: {e}", file=sys.stderr)
            return None

    def write_consolidated(self, output_path, header):
        """Write consolidated audit file"""
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)

            with open(output_path, 'w', encoding='utf-8') as f:
                f.write('# Consolidated audit file - auto-generated by audit_consolidator.py\n')
                f.write(header + '\n\n')

                for item in self.consolidated_items.values():
                    f.write(item + '\n\n')

                f.write('</check_type>\n')

            print(f"✅ Consolidated audit written to: {output_path}")
            print(f"   Total items: {len(self.consolidated_items)}")
            return True

        except Exception as e:
            print(f"❌ Error writing consolidated file: {e}", file=sys.stderr)
            return False

def main():
    if len(sys.argv) < 5:
        print("Usage: audit_consolidator.py <audit_type> <input_audit> <cis_benchmark> <output_file>")
        print("Example: audit_consolidator.py PAFW PAFW_0002.audit CIS_benchmark.audit consolidated.audit")
        sys.exit(1)

    audit_type = sys.argv[1]
    input_audit = Path(sys.argv[2])
    cis_benchmark = Path(sys.argv[3])
    output_file = Path(sys.argv[4])

    if not input_audit.exists():
        print(f"❌ Input audit file not found: {input_audit}", file=sys.stderr)
        sys.exit(1)

    if not cis_benchmark.exists():
        print(f"❌ CIS benchmark file not found: {cis_benchmark}", file=sys.stderr)
        sys.exit(1)

    print(f"Processing {audit_type} audit file...")
    consolidator = AuditConsolidator(str(cis_benchmark))
    header = consolidator.consolidate(str(input_audit), str(cis_benchmark))

    if header:
        consolidator.write_consolidated(output_file, header)
    else:
        print(f"❌ Failed to consolidate audit file", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
