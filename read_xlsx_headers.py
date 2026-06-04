import zipfile
import xml.etree.ElementTree as ET
import os

file_path = os.path.join(os.path.dirname(__file__),  "i-desk Inventory.xlsx")

def get_shared_strings(z):
    try:
        with z.open("xl/sharedStrings.xml") as f:
            tree = ET.parse(f)
            root = tree.getroot()
            # Namespace map
            ns = {'ns': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
            return [node.text if node.text else "" for node in root.findall('.//ns:t', ns)]
    except Exception as e:
        print("No shared strings or error:", e)
        return []

def print_headers():
    try:
        with zipfile.ZipFile(file_path) as z:
            strings = get_shared_strings(z)
            with z.open("xl/worksheets/sheet1.xml") as f:
                tree = ET.parse(f)
                root = tree.getroot()
                ns = {'ns': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
                
                # Let's find cells in row 1
                headers = []
                # Find all 'row' elements
                rows = root.findall('.//ns:row', ns)
                if not rows:
                    print("No rows found!")
                    return
                
                row1 = rows[0]
                cells = row1.findall('ns:c', ns)
                for cell in cells:
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
                
                print("First row of i-desk Inventory.xlsx:")
                print(headers)
                
                # Let's check row 2
                row2_vals = []
                if len(rows) > 1:
                    for cell in rows[1].findall('ns:c', ns):
                        t = cell.get('t')
                        v_node = cell.find('ns:v', ns)
                        if v_node is not None:
                            val = v_node.text
                            if t == 's':
                                row2_vals.append(strings[int(val)])
                            else:
                                row2_vals.append(val)
                        else:
                            row2_vals.append("")
                    print("Second row:")
                    print(row2_vals)
                
                print("Total rows:", len(rows))
    except Exception as e:
        print("Error:", e)

print_headers()
