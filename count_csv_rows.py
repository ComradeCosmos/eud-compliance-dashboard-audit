import csv
import os

files = [
    "ADcomputers-Jun-01-2026.csv",
    "BitLockerInfo_2026-06-01.csv",
    "Nessus agents-06_02_2026_-09_26_44-gmt_5_30.csv",
    "SCCM.csv",
    "Sentinels_Full_Report_20260601_050537_UTC.csv",
    "Zscaler_device_export_2026_06_01-11-23-39.csv"
]

for file in files:
    full_path = os.path.join(os.path.dirname(__file__),  file)
    if os.path.exists(full_path):
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                reader = csv.reader(f)
                headers = next(reader)
                rows = list(reader)
                print(f"File: {file}")
                print(f"  Rows count (excl. header): {len(rows)}")
                
                # Check if there is an asset tag or device name/serial column
                print(f"  Headers: {headers}")
                # Count unique entries in first few columns
                for i in range(min(5, len(headers))):
                    unique_vals = set(row[i].strip() for row in rows if len(row) > i and row[i].strip())
                    print(f"    Col {i} ({headers[i]}): {len(unique_vals)} unique non-empty values")
        except Exception as e:
            print(f"Error reading {file}: {e}")
    else:
        print(f"File not found: {file}")
