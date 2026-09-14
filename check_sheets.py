#!/usr/bin/env python3
import openpyxl

file = r'C:\PySC\TAP\Output\Processed\Normalized\Unique_Controls_Catalog_26091416.xlsx'
try:
    wb = openpyxl.load_workbook(file)
    print(f"Sheet names in {file}:")
    for sheet in wb.sheetnames:
        print(f"  - {sheet}")
except Exception as e:
    print(f"Error: {e}")
