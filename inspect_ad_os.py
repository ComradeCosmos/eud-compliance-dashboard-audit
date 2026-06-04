import csv
import os
from collections import Counter

file_path = os.path.join(os.path.dirname(__file__),  "ADcomputers-Jun-01-2026.csv")
if os.path.exists(file_path):
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        headers = next(reader)
        rows = list(reader)
        os_idx = headers.index("OS")
        c = Counter(row[os_idx].strip() for row in rows if len(row) > os_idx)
        print("OS counts in AD computers CSV:")
        for val, count in c.most_common():
            print(f"  {val}: {count}")
