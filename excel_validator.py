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
    ad_idx = find_index(headers, ["active directory", "ad", "active_directory", "domain"])
    bitlocker_idx = find_index(headers, ["bitlocker", "bit locker", "encryption", "drive encryption", "drive_encryption", "disk encryption"])
    zscaler_idx = find_index(headers, ["zscaler", "zscalar", "z-scaler", "z-scalar", "zscaler client connector", "zscalar client connector", "vpn"])
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
                if val and val not in {"compliant", "non_compliant", "non compliant", "installed", "missing", "yes", "no", "true", "false", "1", "0", "active", "inactive", "disabled", "fail", "failed", "non-compliant", "offline", "critical", "enrolled", "active_enrollment", "active enrollment", "success", "ok", "pass", "passed", "on", "enabled", "running", "secured", "secure", "monitored", "up-to-date", "up to date", "encrypted", "encryption", "protected", "error", "not enrolled", "not_enrolled", "unenrolled", "out of date", "out_of_date", "outdated", "vulnerable"}:
                    warnings.append(f"Row {r_idx}: Compliance field '{agent_name}' value '{row[idx]}' contains non-standard text.")
                    
    return {
        "warnings": warnings,
        "errors": errors
    }

def normalize_value(val):
    if val is None:
        return ""
    val_str = str(val).strip()
    val_low = val_str.lower()
    if val_low in ["disabled", "unknown", "none", "not available", "to be filled by o.e.m.", "-", "outdated", "unreported"]:
        return ""
    return re.sub(r'[^a-zA-Z0-9]', '', val_str).lower()

def norm_mac_list(val):
    if not val:
        return []
    macs = re.findall(r'[0-9a-fA-F]{2}[:.-][0-9a-fA-F]{2}[:.-][0-9a-fA-F]{2}[:.-][0-9a-fA-F]{2}[:.-][0-9a-fA-F]{2}[:.-][0-9a-fA-F]{2}', str(val))
    return [m.lower().replace('.', ':').replace('-', ':') for m in macs]

def get_col_indices(headers):
    h_low = [str(h).lower().strip() for h in headers]
    name_keywords = ["devicename", "hostname", "device", "host", "name", "computer", "machine", "system", "asset"]
    serial_keywords = ["serialnumber", "serial", "s/n", "sn", "uuid", "service tag", "servicetag", "tag"]
    mac_keywords = ["macaddress", "mac", "physical", "ethernet", "hardware"]
    
    def find_idx(keywords):
        for kw in keywords:
            for idx, h in enumerate(h_low):
                if len(kw) <= 3:
                    words = re.split(r'[^a-z0-9]+', h)
                    if kw in words:
                        return idx
                else:
                    if kw in h:
                        return idx
        return -1
        
    return find_idx(name_keywords), find_idx(serial_keywords), find_idx(mac_keywords)

def row_matches(prim_row, prim_meta, sec_row, sec_meta):
    prim_key_val = normalize_value(prim_row[prim_meta['key_idx']]) if prim_meta['key_idx'] < len(prim_row) else ""
    sec_key_val = normalize_value(sec_row[sec_meta['key_idx']]) if sec_meta['key_idx'] < len(sec_row) else ""
    if prim_key_val and prim_key_val == sec_key_val:
        return True
        
    if prim_meta['name_idx'] != -1 and sec_meta['name_idx'] != -1:
        p_name = normalize_value(prim_row[prim_meta['name_idx']]) if prim_meta['name_idx'] < len(prim_row) else ""
        s_name = normalize_value(sec_row[sec_meta['name_idx']]) if sec_meta['name_idx'] < len(sec_row) else ""
        if p_name and p_name == s_name:
            return True
            
    if prim_meta['serial_idx'] != -1 and sec_meta['serial_idx'] != -1:
        p_serial = normalize_value(prim_row[prim_meta['serial_idx']]) if prim_meta['serial_idx'] < len(prim_row) else ""
        s_serial = normalize_value(sec_row[sec_meta['serial_idx']]) if sec_meta['serial_idx'] < len(sec_row) else ""
        if p_serial and p_serial == s_serial:
            return True
            
    if prim_meta['mac_idx'] != -1 and sec_meta['mac_idx'] != -1:
        p_mac_val = prim_row[prim_meta['mac_idx']] if prim_meta['mac_idx'] < len(prim_row) else ""
        s_mac_val = sec_row[sec_meta['mac_idx']] if sec_meta['mac_idx'] < len(sec_row) else ""
        p_macs = norm_mac_list(p_mac_val)
        s_macs = norm_mac_list(s_mac_val)
        if p_macs and s_macs:
            if set(p_macs) & set(s_macs):
                return True
                
    return False

def reconcile_sheets_data(primary_sheet, secondary_sheets):
    """Executes reconciliation logic across a primary sheet and multiple secondary sheets."""
    primary_key_idx = primary_sheet["keyIdx"]
    primary_headers = primary_sheet["headers"]
    primary_rows = primary_sheet["rows"]
    
    prim_name_idx, prim_serial_idx, prim_mac_idx = get_col_indices(primary_headers)
    prim_meta = {
        'key_idx': primary_key_idx,
        'name_idx': prim_name_idx,
        'serial_idx': prim_serial_idx,
        'mac_idx': prim_mac_idx
    }
    
    sec_sheets_processed = []
    for sheet in secondary_sheets:
        key_idx = sheet["keyIdx"]
        headers = sheet["headers"]
        rows = sheet["rows"]
        
        valid_rows = []
        for r in rows:
            if r and not all(str(c).strip() == "" for c in r):
                valid_rows.append(r)
                
        name_idx, serial_idx, mac_idx = get_col_indices(headers)
        sec_meta = {
            'key_idx': key_idx,
            'name_idx': name_idx,
            'serial_idx': serial_idx,
            'mac_idx': mac_idx
        }
        
        sec_sheets_processed.append({
            "filename": sheet["filename"],
            "headers": headers,
            "rows": valid_rows,
            "meta": sec_meta,
            "matched_indices": set()
        })
        
    matches = []
    gaps = []
    
    import random
    
    for p_row_idx, p_row in enumerate(primary_rows):
        if not p_row or all(str(c).strip() == "" for c in p_row):
            continue
            
        raw_name = str(p_row[primary_key_idx]).strip() if primary_key_idx < len(p_row) else f"Device-{p_row_idx + 1}"
        
        present_in_sheets = []
        missing_in_sheets = []
        merged_properties = []
        
        # Capture primary properties
        for idx, h in enumerate(primary_headers):
            if idx != primary_key_idx:
                val = str(p_row[idx]).strip() if idx < len(p_row) else ""
                merged_properties.append({
                    "source": primary_sheet["filename"],
                    "sheetRole": "Primary",
                    "property": h,
                    "value": val if val else "-"
                })
                
        # Resolve secondary mappings
        for sec in sec_sheets_processed:
            matched_row = None
            for r_idx, s_row in enumerate(sec["rows"]):
                if row_matches(p_row, prim_meta, s_row, sec["meta"]):
                    matched_row = s_row
                    sec["matched_indices"].add(r_idx)
                    break
                    
            if matched_row is not None:
                present_in_sheets.append(sec["filename"])
                for idx, h in enumerate(sec["headers"]):
                    if idx != sec["meta"]["key_idx"]:
                        val = str(matched_row[idx]).strip() if idx < len(matched_row) else ""
                        merged_properties.append({
                            "source": sec["filename"],
                            "sheetRole": "Secondary",
                            "property": h,
                            "value": val if val else "-"
                        })
            else:
                missing_in_sheets.append(sec["filename"])
                
        random_suffix = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=4))
        
        if len(missing_in_sheets) > 0:
            gaps.append({
                "id": f"dev-gap-{random_suffix}",
                "name": raw_name,
                "normalized": normalize_value(raw_name),
                "primaryRow": p_row,
                "missingInSheets": missing_in_sheets,
                "presentInSheets": present_in_sheets,
                "mergedProperties": merged_properties,
                "status": "COVERAGE_GAP"
            })
        else:
            matches.append({
                "id": f"dev-rec-{random_suffix}",
                "name": raw_name,
                "normalized": normalize_value(raw_name),
                "primaryRow": p_row,
                "mergedProperties": merged_properties,
                "status": "MATCHED"
            })
            
    # Resolve rogue assets
    rogues_map = {}
    for sec in sec_sheets_processed:
        for r_idx, s_row in enumerate(sec["rows"]):
            if r_idx not in sec["matched_indices"]:
                val = str(s_row[sec["meta"]["key_idx"]]).strip() if sec["meta"]["key_idx"] < len(s_row) else ""
                if not val:
                    continue
                norm_name = normalize_value(val)
                if not norm_name:
                    continue
                if norm_name not in rogues_map:
                    rogues_map[norm_name] = {
                        "name": val,
                        "sheets": []
                    }
                rogues_map[norm_name]["sheets"].append({
                    "filename": sec["filename"],
                    "row": s_row,
                    "headers": sec["headers"],
                    "keyIdx": sec["meta"]["key_idx"]
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

