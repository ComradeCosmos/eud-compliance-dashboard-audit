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
                print(f"File: {file}")
                print(f"  Headers: {headers}")
                # Print first row
                row1 = next(reader)
                print(f"  Row 1  : {row1}\n")
        except Exception as e:
            print(f"Error reading {file}: {e}\n")
    else:
        print(f"File not found: {file}\n")
