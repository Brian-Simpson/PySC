#!/usr/bin/env python3
"""
TAP UNIFIED PIPELINE - DOCUMENTED STEP-BY-STEP EXECUTION
Shows exactly what happens at each stage and documents the files
"""
import sys
import subprocess
from pathlib import Path
from datetime import datetime


def log_step(step_num, title):
    print(f"\n{'='*80}")
    print(f"STEP {step_num}: {title}")
    print(f"{'='*80}")


def log_detail(msg, file_path=None, size=None):
    detail = f"  {msg}"
    if file_path:
        detail += f" | {file_path}"
    if size:
        detail += f" | {size} bytes"
    print(detail)


def check_file(path):
    """Check if file exists and return size"""
    if path.exists():
        return path.stat().st_size
    return None


def main():
    tap_repo = Path(r"c:\PySC\TAP")
    baseline_input = tap_repo / 'actual_audit_inputs' / 'HTH_Baseline_NETPAFW.audit'
    rebuilt_output = tap_repo / 'Output' / 'PAFW.audit'
    for_gap_source = tap_repo / 'actual_audit_inputs' / 'For_Gap' / 'PAFW.audit'
    for_gap_output = Path(r"c:\PySC\TAP\Output\Processed\For_Gap\PAFW.audit")

    print("\n" + "="*80)
    print("TAP UNIFIED PIPELINE EXECUTION DOCUMENTATION")
    print(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*80)

    # STEP 1: Rebuild PAFW
    log_step(1, "Rebuild PAFW.audit with validated XSLT")
    log_detail("INPUT", str(baseline_input))
    size_before = check_file(baseline_input)
    if size_before:
        log_detail("Baseline audit size", size=size_before)

    log_detail("Running rebuild...")
    cmd = [sys.executable, '-c', '''
import sys
sys.path.insert(0, r"c:\\PySC\\TAP")
from tap_unified import TAPPipeline
pipeline = TAPPipeline()
pipeline.rebuild_pafw_audit()
''']

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print("ERROR:", result.stderr)
        return False

    size_rebuilt = check_file(rebuilt_output)
    if size_rebuilt:
        log_detail("OUTPUT", str(rebuilt_output), size=size_rebuilt)
    else:
        log_detail("ERROR: Rebuilt file not found!")
        return False

    # STEP 2: TAP Refresh
    log_step(2, "TAP refresh pipeline (normalize → catalog → merge → gap → consolidate)")
    log_detail("Running TAP refresh from", str(tap_repo))

    cmd = [sys.executable, '-m', 'tap', 'refresh']
    result = subprocess.run(cmd, cwd=str(tap_repo), capture_output=True, text=True)
    if result.returncode != 0:
        print("ERROR:", result.stderr[:500])
        return False

    # Check outputs
    log_detail("Checking consolidation outputs...")

    size_for_gap_source = check_file(for_gap_source)
    if size_for_gap_source:
        log_detail("For_Gap source created", str(for_gap_source), size=size_for_gap_source)
    else:
        log_detail("ERROR: For_Gap source not found!")

    size_for_gap_output = check_file(for_gap_output)
    if size_for_gap_output:
        log_detail("For_Gap output created", str(for_gap_output), size=size_for_gap_output)
    else:
        log_detail("ERROR: For_Gap output not found!")

    # STEP 3: Analyze corruption
    log_step(3, "ANALYZE: Check for corrupted xsl_stmt fields")

    if for_gap_source.exists():
        with open(for_gap_source, 'r', encoding='utf-8') as f:
            content = f.read()
            if 'regex' in content and '<xsl:template match' in content:
                # Check if regex appears in same field as xsl_stmt
                corrupted_count = content.count('xsl_stmt         : "<xsl:template match')
                log_detail(f"Found {corrupted_count} potential corrupted xsl_stmt entries")
            else:
                log_detail("No obvious corruption found in source")

    print("\n" + "="*80)
    print("DOCUMENTATION SUMMARY")
    print("="*80)
    print(f"Baseline input size:        {size_before:,} bytes")
    print(f"Rebuilt PAFW size:          {size_rebuilt:,} bytes" if size_rebuilt else "Not created")
    print(f"TAP consolidated size:      {size_for_gap_source:,} bytes" if size_for_gap_source else "Not created")
    print(f"For_Gap output size:        {size_for_gap_output:,} bytes" if size_for_gap_output else "Not created")

    if size_for_gap_source and size_for_gap_output:
        ratio = size_for_gap_output / size_for_gap_source if size_for_gap_source else 0
        print(f"Size ratio (output/source):  {ratio:.2f}x")

    print(f"\nEnd time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*80)

    return True


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
