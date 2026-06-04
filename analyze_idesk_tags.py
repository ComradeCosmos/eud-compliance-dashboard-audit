import zipfile
import xml.etree.ElementTree as ET
import os

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
                
                # Check for Asset State == 'In Use'
                in_use_rows = [r for r in rows_data if r.get('Asset State') == 'In Use']
                print(f"Total 'In Use' rows: {len(in_use_rows)}")
                
                # Check unique Asset Tags for 'In Use' rows
                asset_tags_in_use = [r.get('Asset Tag') for r in in_use_rows]
                unique_tags_in_use = set(asset_tags_in_use)
                print(f"Unique 'Asset Tag' values in 'In Use': {len(unique_tags_in_use)}")
                
                # Are there any empty tags or 'Not Assigned' or '-' tags?
                special_tags = ["", "not assigned", "-", "n/a", "null", "none"]
                filtered_tags_in_use = [t for t in asset_tags_in_use if t.lower() not in special_tags]
                print(f"Non-empty, valid 'Asset Tag' values in 'In Use': {len(filtered_tags_in_use)}")
                print(f"Unique non-empty, valid 'Asset Tag' values in 'In Use': {len(set(filtered_tags_in_use))}")
                
                # Let's count how many tags contain 'not assigned' or similar
                not_assigned_tags = [t for t in asset_tags_in_use if 'assigned' in t.lower() or 'not' in t.lower()]
                print(f"Tags with 'assigned' or 'not': {len(not_assigned_tags)}")
                
                # Let's print unique values in 'Asset Tag' that aren't typical
                # A standard asset tag might start with LT or DT or be alphanumeric
                # Let's see if we can find how many are valid/invalid
                
    except Exception as e:
        print("Error:", e)

analyze()
