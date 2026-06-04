import zipfile
import xml.etree.ElementTree as ET
import os
from collections import Counter

file_path = os.path.join(os.path.dirname(__file__),  "i-desk Inventory.xlsx")

def get_shared_strings(z):
    try:
        with z.open("xl/sharedStrings.xml") as f:
            tree = ET.parse(f)
            root = tree.getroot()
            ns = {'ns': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
            return [node.text if node.text else "" for node in root.findall('.//ns:t', ns)]
    except Exception as e:
        print("No shared strings or error:", e)
        return []

def analyze():
    try:
        with zipfile.ZipFile(file_path) as z:
            strings = get_shared_strings(z)
            with z.open("xl/worksheets/sheet1.xml") as f:
                tree = ET.parse(f)
                root = tree.getroot()
                ns = {'ns': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
                
                rows = root.findall('.//ns:row', ns)
                if not rows:
                    return
                
                header_row = rows[0]
                headers = []
                for cell in header_row.findall('ns:c', ns):
                    t = cell.get('t')
                    v_node = cell.find('ns:v', ns)
                    if v_node is not None:
                        val = v_node.text
                        if t == 's':
                            headers.append(strings[int(val)])
                        else:
                            headers.append(val)
                    else:
                        headers.append("")
                
                rows_data = []
                for r_idx, row in enumerate(rows[1:], start=2):
                    cells = row.findall('ns:c', ns)
                    row_vals = {}
                    for cell in cells:
                        ref = cell.get('r')
                        col_letters = ''.join([c for c in ref if c.isalpha()])
                        col_idx = 0
                        for char in col_letters:
                            col_idx = col_idx * 26 + (ord(char) - ord('A') + 1)
                        col_idx -= 1
                        
                        t = cell.get('t')
                        v_node = cell.find('ns:v', ns)
                        val = ""
                        if v_node is not None:
                            v_text = v_node.text
                            if t == 's':
                                val = strings[int(v_text)]
                            else:
                                val = v_text
                        row_vals[col_idx] = val
                    
                    row_dict = {}
                    for idx, h in enumerate(headers):
                        row_dict[h] = row_vals.get(idx, "").strip()
                    rows_data.append(row_dict)
                
                print("Total rows:", len(rows_data))
                
                # Let's count unique values for some fields
                for col in ['Asset State', 'Sub_State', 'Asset Category', 'Asset Type', 'Sub_Asset_Type', 'Make']:
                    c = Counter(r.get(col, "") for r in rows_data)
                    print(f"\nValue counts for '{col}':")
                    for val, count in c.most_common():
                        print(f"  {val}: {count}")
                
                # Check for specific filtered counts
                # E.g. Asset State == 'In Use'
                in_use = [r for r in rows_data if r.get('Asset State') == 'In Use']
                print(f"\n'In Use' count: {len(in_use)}")
                
                # Asset Category == 'IT' or 'Non-IT' or something?
                # Wait, does any combination equal 10,029?
                # Let's check different combinations
                it_assets = [r for r in rows_data if r.get('Asset Category') == 'IT']
                print(f"Asset Category 'IT' count: {len(it_assets)}")
                
                it_in_use = [r for r in rows_data if r.get('Asset Category') == 'IT' and r.get('Asset State') == 'In Use']
                print(f"Asset Category 'IT' and State 'In Use' count: {len(it_in_use)}")

                # Let's see: what if we check for active asset tags in the frontend code?
                
    except Exception as e:
        print("Error:", e)

analyze()
