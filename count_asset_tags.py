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

def count_tags():
    try:
        with zipfile.ZipFile(file_path) as z:
            strings = get_shared_strings(z)
            with z.open("xl/worksheets/sheet1.xml") as f:
                tree = ET.parse(f)
                root = tree.getroot()
                ns = {'ns': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
                
                rows = root.findall('.//ns:row', ns)
                if not rows:
                    print("No rows found!")
                    return
                
                # First find the index of 'Asset Tag'
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
                
                print("Headers:", headers)
                
                asset_tag_col_idx = -1
                for idx, h in enumerate(headers):
                    if h.strip().lower() == 'asset tag':
                        asset_tag_col_idx = idx
                        break
                
                if asset_tag_col_idx == -1:
                    print("Asset Tag column not found!")
                    return
                
                print(f"Asset Tag is at column index: {asset_tag_col_idx}")
                
                total_asset_tags = 0
                unique_asset_tags = set()
                non_empty_count = 0
                
                for r_idx, row in enumerate(rows[1:], start=2):
                    # We need to map cells to their column index. Excel cells use 'r' attribute like 'A2', 'B2', etc.
                    # A simple way is to build a list of values for the row by parsing cell refs, or just keep track of cell count.
                    # Note: Excel rows can omit empty cells. So we must parse the column from cell reference 'r'.
                    cells = row.findall('ns:c', ns)
                    row_vals = {}
                    for cell in cells:
                        ref = cell.get('r')
                        # Extract column letters from ref (e.g. 'AC2' -> 'AC')
                        col_letters = ''.join([c for c in ref if c.isalpha()])
                        # Convert col_letters to 0-based index
                        col_idx = 0
                        for char in col_letters:
                            col_idx = col_idx * 26 + (ord(char) - ord('A') + 1)
                        col_idx -= 1 # 0-based
                        
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
                    
                    asset_tag = row_vals.get(asset_tag_col_idx, "").strip()
                    if asset_tag:
                        non_empty_count += 1
                        unique_asset_tags.add(asset_tag.lower())
                
                print(f"Total rows (excluding header): {len(rows) - 1}")
                print(f"Non-empty Asset Tag count: {non_empty_count}")
                print(f"Unique Asset Tag count: {len(unique_asset_tags)}")
                
    except Exception as e:
        print("Error:", e)

count_tags()
