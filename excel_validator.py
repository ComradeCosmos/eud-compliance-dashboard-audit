import os
import re
import csv
import io
import zipfile
import xml.etree.ElementTree as ET

# Regular Expression for MAC Address validation
MAC_REGEX = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
# Regular Expression for standard corporate hostnames
HOSTNAME_REGEX = re.compile(r'^[a-zA-Z0-9-]+$')
# Regular Expression for timestamps like "2026-05-27 14:30" or "2026-05-27"
DATE_REGEX = re.compile(r'^\d{4}-\d{2}-\d{2}( \d{2}:\d{2})?$')

def is_valid_ip(ip_str):
    """Checks if a string is a valid IPv4 address."""
    parts = ip_str.split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        try:
            val = int(part)
            if val < 0 or val > 255:
                return False
        except ValueError:
            return False
    return True

def is_valid_mac(mac_str):
    """Checks if a string matches a standard MAC address format."""
    return bool(MAC_REGEX.match(mac_str))

def is_valid_hostname(host_str):
    """Checks if a hostname contains only alphanumeric and hyphens."""
    return bool(HOSTNAME_REGEX.match(host_str))

def is_valid_date(date_str):
    """Checks if a date matches the YYYY-MM-DD or YYYY-MM-DD HH:MM pattern."""
    return bool(DATE_REGEX.match(date_str))

def find_index(headers, keywords):
    """Fuzzy maps headers to find column index using keyword matching rules."""
    for kw in keywords:
        for idx, h in enumerate(headers):
            h_lower = str(h).lower().strip()
            if len(kw) <= 3:
                # Whole word match for short keywords (e.g., ad, mac, sn)
                words = re.split(r'[^a-z0-9]+', h_lower)
                if kw in words:
                    return idx
            else:
                if kw in h_lower:
                    return idx
    return -1

def get_shared_strings(z):
    """Reads sharedStrings.xml from the XLSX zip archive."""
    try:
        with z.open("xl/sharedStrings.xml") as f:
            tree = ET.parse(f)
            root = tree.getroot()
            ns = {'ns': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
            
            strings = []
            for si in root.findall('.//ns:si', ns):
                t_nodes = si.findall('.//ns:t', ns)
                val = "".join([t.text for t in t_nodes if t.text])
                strings.append(val)
            return strings
    except Exception:
        return []

def parse_xlsx(file_bytes):
    """Parses a zip-compressed .xlsx file bytes using ElementTree, returning rows."""
    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes)) as z:
            strings = get_shared_strings(z)
            
            # Locate first sheet XML
            sheet_file = None
            for name in z.namelist():
                if name.startswith("xl/worksheets/sheet") and name.endswith(".xml"):
                    sheet_file = name
                    break
            
            if not sheet_file:
                sheet_file = "xl/worksheets/sheet1.xml"
                
            with z.open(sheet_file) as f:
                tree = ET.parse(f)
                root = tree.getroot()
                ns = {'ns': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
                
                rows_nodes = root.findall('.//ns:row', ns)
                if not rows_nodes:
                    return []
                
                parsed_rows = []
                for row_node in rows_nodes:
                    cells = row_node.findall('ns:c', ns)
                    row_vals = {}
                    max_col_idx = 0
                    for cell in cells:
                        ref = cell.get('r')
                        if not ref:
                            continue
                        
                        # Translate cell reference (e.g. AA12 -> column index)
                        col_letters = ''.join([c for c in ref if c.isalpha()])
                        col_idx = 0
                        for char in col_letters:
                            col_idx = col_idx * 26 + (ord(char) - ord('A') + 1)
                        col_idx -= 1
                        
                        if col_idx > max_col_idx:
                            max_col_idx = col_idx
                        
                        t = cell.get('t')
                        v_node = cell.find('ns:v', ns)
                        val = ""
                        if v_node is not None:
                            v_text = v_node.text or ""
                            if t == 's':
                                try:
                                    val = strings[int(v_text)]
                                except (ValueError, IndexError):
                                    val = v_text
                            elif t == 'str':
                                val = v_text
                            else:
                                val = v_text
                        row_vals[col_idx] = val
                    
                    row_list = [row_vals.get(i, "") for i in range(max_col_idx + 1)]
                    parsed_rows.append(row_list)
                
                if parsed_rows:
                    max_len = max(len(r) for r in parsed_rows)
                    for r in parsed_rows:
                        while len(r) < max_len:
                            r.append("")
                return parsed_rows
    except Exception as e:
        raise ValueError(f"Failed to parse Excel spreadsheet: {e}")

def parse_csv(file_content_str):
    """Parses a CSV string, dynamically sniffing delimiters, returning rows."""
    try:
        sample = file_content_str[:4096]
        dialect = csv.Sniffer().sniff(sample)
        delimiter = dialect.delimiter
    except Exception:
        # Fallback delimiters
        first_line = file_content_str.split('\n')[0]
        if ';' in first_line and ',' not in first_line:
            delimiter = ';'
        elif '\t' in first_line:
            delimiter = '\t'
        else:
            delimiter = ','
            
    reader = csv.reader(io.StringIO(file_content_str), delimiter=delimiter)
    return list(reader)

def validate_sheet_data(headers, rows):
    """Validates structural constraints and field formats inside the sheet rows."""
    # Fuzzy match column headers
    device_name_idx = find_index(headers, ["devicename", "hostname", "device", "host", "name", "computer", "machine", "system"])
    serial_idx = find_index(headers, ["serialnumber", "serial", "s/n", "sn", "uuid", "service tag", "servicetag", "tag"])
    mac_idx = find_index(headers, ["macaddress", "mac", "physical", "ethernet", "hardware"])
    last_login_idx = find_index(headers, ["lastlogin", "login", "active", "date", "time"])
    condition_idx = find_index(headers, ["condition", "status", "state"])
    ip_idx = find_index(headers, ["ip", "ipaddress", "ip_address", "subnet"])
    
    # Core compliance controls
    ad_idx = find_index(headers, ["active directory", "ad", "active_directory", "domain", "enrollment"])
    bitlocker_idx = find_index(headers, ["bitlocker", "bit locker", "encryption", "drive encryption", "drive_encryption", "disk encryption"])
    zscaler_idx = find_index(headers, ["zscaler", "z-scaler", "zscaler client connector", "vpn"])
    nessus_idx = find_index(headers, ["nessus", "tenable", "vulnerability agent", "nessus agent", "scanner"])
    s1_idx = find_index(headers, ["sentinelone", "sentinel one", "s1", "endpoint agent", "edr", "antivirus"])
    sccm_idx = find_index(headers, ["sccm", "sccm agent", "mecm", "management agent", "patch agent"])
    
    warnings = []
    errors = []
    
    if device_name_idx == -1:
        warnings.append("No hostname/device name column auto-detected. Defaulting to Col 1.")
        device_name_idx = 0
        
    for r_idx, row in enumerate(rows, start=2):
        if not row or all(str(cell).strip() == "" for cell in row):
            continue
            
        while len(row) < len(headers):
            row.append("")
            
        # 1. Device Name Validation
        dev_name = str(row[device_name_idx]).strip()
        if not dev_name:
            errors.append(f"Row {r_idx}: Device name field is blank.")
        elif not is_valid_hostname(dev_name):
            warnings.append(f"Row {r_idx}: Device name '{dev_name}' has non-standard chars (only letters, numbers, and hyphens allowed).")
            
        # 2. Serial Validation
        if serial_idx != -1:
            serial_val = str(row[serial_idx]).strip()
            if not serial_val:
                warnings.append(f"Row {r_idx}: Serial Number is empty.")
            elif len(serial_val) < 4:
                warnings.append(f"Row {r_idx}: Serial Number '{serial_val}' is suspiciously short.")
                
        # 3. MAC Validation
        if mac_idx != -1:
            mac_val = str(row[mac_idx]).strip()
            if mac_val and mac_val != "-" and not is_valid_mac(mac_val):
                warnings.append(f"Row {r_idx}: MAC Address '{mac_val}' is invalid. Expected format XX:XX:XX:XX:XX:XX.")
                
        # 4. IP Validation
        if ip_idx != -1:
            ip_val = str(row[ip_idx]).strip()
            if ip_val and ip_val != "-" and not is_valid_ip(ip_val):
                warnings.append(f"Row {r_idx}: Subnet IP address '{ip_val}' is invalid.")
                
        # 5. Last Login Validation
        if last_login_idx != -1:
            login_val = str(row[last_login_idx]).strip()
            if login_val and login_val != "-" and not is_valid_date(login_val):
                warnings.append(f"Row {r_idx}: Last Login Date '{login_val}' is non-standard (expected YYYY-MM-DD HH:MM).")
                
        # 6. Asset State Validation
        if condition_idx != -1:
            cond_val = str(row[condition_idx]).strip().upper().replace(" ", "_")
            valid_conditions = {"IN_USE", "IN_REPAIR", "IN_STORE", "EXPIRED", "DISPOSED", "DECOMMISSIONED", "LOANABLE_RESERVED", "NOT_TRACEABLE", "RESERVED"}
            if cond_val and cond_val not in valid_conditions:
                # Check fuzzy normalization match
                norm_cond = cond_val.replace("-", "_")
                if norm_cond not in {"IN_USE", "USE", "ACTIVE", "IN_REPAIR", "REPAIR", "IN_STORE", "STORE", "EXPIRED", "DISPOSED", "DECOMMISSIONED", "RETIRED", "DONATED_UNDER_CSR", "DONATED", "CSR", "LOANABLE_RESERVED", "LOANABLE", "NOT_TRACEABLE", "UNTRACEABLE", "RESERVED"}:
                    warnings.append(f"Row {r_idx}: Condition state '{row[condition_idx]}' is unrecognized.")
                    
        # 7. Agent Compliance Values Validation
        for agent_name, idx in [("AD Enrollment", ad_idx), ("BitLocker", bitlocker_idx), ("Zscaler vpn", zscaler_idx), ("Nessus agent", nessus_idx), ("SentinelOne edr", s1_idx), ("SCCM patch", sccm_idx)]:
            if idx != -1:
                val = str(row[idx]).strip().lower()
                if val and val not in {"compliant", "non_compliant", "installed", "missing", "yes", "no", "true", "false", "1", "0", "active", "inactive", "disabled", "fail", "failed", "non-compliant", "offline", "critical"}:
                    warnings.append(f"Row {r_idx}: Compliance field '{agent_name}' value '{row[idx]}' contains non-standard text.")
                    
    return {
        "warnings": warnings,
        "errors": errors
    }

def reconcile_sheets_data(primary_sheet, secondary_sheets):
    """Executes reconciliation logic across a primary sheet and multiple secondary sheets."""
    primary_key_idx = primary_sheet["keyIdx"]
    primary_headers = primary_sheet["headers"]
    primary_rows = primary_sheet["rows"]
    
    primary_map = {}
    for row in primary_rows:
        if not row or all(str(c).strip() == "" for c in row):
            continue
        val = str(row[primary_key_idx]).strip() if primary_key_idx < len(row) else ""
        if not val:
            continue
        norm_name = re.sub(r'[^a-zA-Z0-9]', '', val).lower()
        primary_map[norm_name] = {
            "rawName": val,
            "row": row
        }
        
    secondary_maps = []
    for sheet in secondary_sheets:
        key_idx = sheet["keyIdx"]
        headers = sheet["headers"]
        rows = sheet["rows"]
        
        sheet_map = {}
        for row in rows:
            if not row or all(str(c).strip() == "" for c in row):
                continue
            val = str(row[key_idx]).strip() if key_idx < len(row) else ""
            if not val:
                continue
            norm_name = re.sub(r'[^a-zA-Z0-9]', '', val).lower()
            sheet_map[norm_name] = row
            
        secondary_maps.append({
            "filename": sheet["filename"],
            "headers": headers,
            "keyIdx": key_idx,
            "map": sheet_map
        })
        
    matches = []
    gaps = []
    
    import random
    
    for norm_name, primary_data in primary_map.items():
        present_in_sheets = []
        missing_in_sheets = []
        merged_properties = []
        
        # Capture primary properties
        for idx, h in enumerate(primary_headers):
            if idx != primary_key_idx:
                val = str(primary_data["row"][idx]).strip() if idx < len(primary_data["row"]) else ""
                merged_properties.append({
                    "source": primary_sheet["filename"],
                    "sheetRole": "Primary",
                    "property": h,
                    "value": val if val else "-"
                })
                
        # Resolve secondary mappings
        for sec in secondary_maps:
            if norm_name in sec["map"]:
                present_in_sheets.append(sec["filename"])
                row_data = sec["map"][norm_name]
                
                for idx, h in enumerate(sec["headers"]):
                    if idx != sec["keyIdx"]:
                        val = str(row_data[idx]).strip() if idx < len(row_data) else ""
                        merged_properties.append({
                            "source": sec["filename"],
                            "sheetRole": "Secondary",
                            "property": h,
                            "value": val if val else "-"
                        })
            else:
                missing_in_sheets.append(sec["filename"])
                
        # Generate random unique suffix matching JS format
        random_suffix = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=4))
        
        if len(missing_in_sheets) > 0:
            gaps.append({
                "id": f"dev-gap-{random_suffix}",
                "name": primary_data["rawName"],
                "normalized": norm_name,
                "primaryRow": primary_data["row"],
                "missingInSheets": missing_in_sheets,
                "presentInSheets": present_in_sheets,
                "mergedProperties": merged_properties,
                "status": "COVERAGE_GAP"
            })
        else:
            matches.append({
                "id": f"dev-rec-{random_suffix}",
                "name": primary_data["rawName"],
                "normalized": norm_name,
                "primaryRow": primary_data["row"],
                "mergedProperties": merged_properties,
                "status": "MATCHED"
            })
            
    # Resolve rogue assets
    rogues_map = {}
    for sec in secondary_maps:
        for norm_name, row in sec["map"].items():
            if norm_name not in primary_map:
                if norm_name not in rogues_map:
                    val = str(row[sec["keyIdx"]]).strip() if sec["keyIdx"] < len(row) else ""
                    rogues_map[norm_name] = {
                        "name": val,
                        "sheets": []
                    }
                rogues_map[norm_name]["sheets"].append({
                    "filename": sec["filename"],
                    "row": row,
                    "headers": sec["headers"],
                    "keyIdx": sec["keyIdx"]
                })
                
    rogues = []
    for norm_name, rogue_obj in rogues_map.items():
        random_suffix = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=4))
        rogues.append({
            "id": f"dev-rogue-{random_suffix}",
            "name": rogue_obj["name"],
            "normalized": norm_name,
            "sheets": rogue_obj["sheets"],
            "status": "ROGUE_UNMANAGED"
        })
        
    return {
        "matches": matches,
        "gaps": gaps,
        "rogues": rogues
    }
