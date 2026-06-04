import zipfile
import xml.etree.ElementTree as ET
import os

file_path = os.path.join(os.path.dirname(__file__),  "i-desk Inventory.xlsx")

def check_sheets():
    try:
        with zipfile.ZipFile(file_path) as z:
            # Let's read workbook.xml to get sheet names
            with z.open("xl/workbook.xml") as f:
                tree = ET.parse(f)
                root = tree.getroot()
                ns = {'ns': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
                sheets = root.findall('.//ns:sheet', ns)
                print("Sheets in workbook:")
                for sheet in sheets:
                    name = sheet.get('name')
                    sheet_id = sheet.get('sheetId')
                    r_id = sheet.get('{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id')
                    print(f"  Name: {name}, SheetID: {sheet_id}, rId: {r_id}")
                    
            # Let's count worksheets in the zip
            for name in z.namelist():
                if name.startswith("xl/worksheets/"):
                    print(f"Worksheet file: {name}")
                    with z.open(name) as f:
                        t = ET.parse(f)
                        r = t.getroot()
                        ns = {'ns': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
                        rows = r.findall('.//ns:row', ns)
                        print(f"    Rows count: {len(rows)}")
    except Exception as e:
        print("Error:", e)

check_sheets()
