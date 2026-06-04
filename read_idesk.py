import pandas as pd
import os

file_path = os.path.join(os.path.dirname(__file__),  "i-desk Inventory.xlsx")
try:
    df = pd.read_excel(file_path)
    print("Columns found in i-desk Inventory:")
    print(list(df.columns))
    print("\nRow 1:")
    print(df.iloc[0].to_dict())
    print("\nRow 2:")
    print(df.iloc[1].to_dict())
    print("\nTotal rows:", len(df))
except Exception as e:
    print("Error:", e)
