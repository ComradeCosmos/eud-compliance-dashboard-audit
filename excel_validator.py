import os
import re
import csv
import io
import zipfile
import xml.etree.ElementTree as ET

# ==============================================================================
# REGULAR EXPRESSIONS & UTILITY VALIDATORS
# ==============================================================================

# Standard MAC Address formats (e.g. 00:1A:2B:3C:4D:5E or 00-1A-2B-3C-4D-5E)
MAC_REGEX = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')

# Corporate Hostnames (alphanumeric and hyphens only)
HOSTNAME_REGEX = re.compile(r'^[a-zA-Z0-9-]+$')

# Audit Dates (YYYY-MM-DD or YYYY-MM-DD HH:MM)
DATE_REGEX = re.compile(r'^\d{4}-\d{2}-\d{2}( \d{2}:\d{2})?$')

def is_valid_ip(ip_str):
    """Verifies if a string is a valid IPv4 address."""
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
    """Verifies if a MAC address matches standard formats."""
    return bool(MAC_REGEX.match(mac_str))

def is_valid_hostname(host_str):
    """Verifies hostnames against corporate characters constraint (alphanumeric and hyphens)."""
    return bool(HOSTNAME_REGEX.match(host_str))

def is_valid_date(date_str):
    """Checks date formats (expected standard YYYY-MM-DD format)."""
    return bool(DATE_REGEX.match(date_str))


# ==============================================================================
# FUZZY COLUMN MAPPING
# ==============================================================================

def find_index(headers, keywords):
    """
    Finds the index of a header matching any of the given keywords.
    Ensures short word tokens match exactly, and handles special exclusions 
    (e.g., preventing Active Directory (AD) columns from matching third-party software agents).
    """
    is_ad = any(k in keywords for k in ["ad", "active directory", "active_directory"])
    for kw in keywords:
        for idx, h in enumerate(headers):
            h_lower = str(h).lower().strip()
            
            # Exclude Active Directory properties for non-AD agents (e.g. S1, Nessus, Zscaler)
            if not is_ad:
                words = re.split(r'[^a-z0-9]+', h_lower)
                if "ad" in words or "active directory" in h_lower or "active_directory" in h_lower:
                    continue
                    
            if len(kw) <= 3:
                # Require exact full-word match for short strings (e.g. 'ad', 'mac', 'sn')
                words = re.split(r'[^a-z0-9]+', h_lower)
                if kw in words:
                    return idx
            else:
                # Substring match for longer descriptive keywords
                if kw in h_lower:
                    return idx
    return -1


# ==============================================================================
# PURE PYTHON SPREADSHEET PARSING (Zero Dependencies)
# ==============================================================================

def get_shared_strings(z):
    """
    Reads the sharedStrings.xml file in an XLSX zip archive.
    Excel compresses string data into a single file and references them by index.
    """
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
    """
    Parses a standard .xlsx zipped spreadsheet file using standard xml parser.
    Builds a list of rows, dynamically expanding empty cells and translating shared string indexes.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes)) as z:
            strings = get_shared_strings(z)
            
            # Locate first sheet XML (usually xl/worksheets/sheet1.xml)
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
                        
                        # Convert cell reference (e.g. 'AA12' -> column index 26)
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
                                # Resolve string index from sharedStrings.xml
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
                
                # Align row lengths for table structure integrity
                if parsed_rows:
                    max_len = max(len(r) for r in parsed_rows)
                    for r in parsed_rows:
                        while len(r) < max_len:
                            r.append("")
                return parsed_rows
    except Exception as e:
        raise ValueError(f"Failed to parse Excel spreadsheet: {e}")

def parse_csv(file_content_str):
    """Parses raw CSV content string, dynamically sniffing delimiters."""
    try:
        sample = file_content_str[:4096]
        dialect = csv.Sniffer().sniff(sample)
        delimiter = dialect.delimiter
    except Exception:
        # Delimiter heuristics fallback
        first_line = file_content_str.split('\n')[0]
        if ';' in first_line and ',' not in first_line:
            delimiter = ';'
        elif '\t' in first_line:
            delimiter = '\t'
        else:
            delimiter = ','
            
    reader = csv.reader(io.StringIO(file_content_str), delimiter=delimiter)
    return list(reader)


# ==============================================================================
# SPREADSHEET STRUCTURAL AUDIT VALIDATION
# ==============================================================================

def validate_sheet_data(headers, rows, filename=None):
    """
    Validates structural formatting and field layouts of spreadsheet cells.
    Detects warnings (e.g. empty serials, bad MAC formats) and errors (blank hostnames).
    """
    # 1. Map columns fuzzy
    device_name_idx = find_index(headers, ["devicename", "hostname", "device", "host", "name", "computer", "machine", "system"])
    
    is_zscaler = False
    if filename:
        fn_low = str(filename).lower()
        if "zscaler" in fn_low or "zscalar" in fn_low or "zscalr" in fn_low or "vpn" in fn_low:
            is_zscaler = True
            
    if is_zscaler:
        serial_keywords = ["serialnumber", "serial", "s/n", "sn", "uuid", "udid", "externalid", "external device id", "service tag", "servicetag", "tag", "asset tag", "assettag"]
    else:
        serial_keywords = ["serialnumber", "serial", "s/n", "sn", "uuid", "externalid", "external device id", "service tag", "servicetag", "tag", "asset tag", "assettag"]
        
    serial_idx = find_index(headers, serial_keywords)
    mac_idx = find_index(headers, ["macaddress", "mac", "physical", "ethernet", "hardware"])
    last_login_idx = find_index(headers, ["lastlogin", "login", "active", "date", "time"])
    
    is_telemetry = False
    if filename:
        fn_low = str(filename).lower()
        if any(k in fn_low for k in ["sentinel", "s1", "edr", "antivirus", "zscaler", "zscalar", "zscalr", "vpn", "nessus", "tenable", "bitlocker", "sccm", "mecm"]):
            is_telemetry = True
            
    if is_telemetry:
        condition_idx = find_index(headers, ["condition"])
    else:
        condition_idx = find_index(headers, ["condition", "status", "state"])
        
    ip_idx = find_index(headers, ["ip", "ipaddress", "ip_address", "subnet"])
    
    # Core compliance parameters mapping
    ad_idx = find_index(headers, ["active directory", "ad", "active_directory", "domain"])
    bitlocker_idx = find_index(headers, ["bitlocker", "bit locker", "encryption", "drive encryption", "drive_encryption", "disk encryption"])
    zscaler_idx = find_index(headers, ["zscaler", "zscalar", "zscalr", "z-scaler", "z-scalar", "z-scalr", "zscaler client connector", "zscalar client connector", "zscalr client connector", "vpn"])
    nessus_idx = find_index(headers, ["nessus", "tenable", "vulnerability agent", "nessus agent", "scanner"])
    s1_idx = find_index(headers, ["sentinelone", "sentinel one", "s1", "endpoint agent", "edr", "antivirus", "status", "state", "installed", "compliance", "agent status", "agent_status"])
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
                # Fuzzy normalization condition matches
                norm_cond = cond_val.replace("-", "_")
                if norm_cond not in {"IN_USE", "USE", "ACTIVE", "IN_REPAIR", "REPAIR", "IN_STORE", "STORE", "EXPIRED", "DISPOSED", "DECOMMISSIONED", "RETIRED", "DONATED_UNDER_CSR", "DONATED", "CSR", "LOANABLE_RESERVED", "LOANABLE", "NOT_TRACEABLE", "UNTRACEABLE", "RESERVED"}:
                    warnings.append(f"Row {r_idx}: Condition state '{row[condition_idx]}' is unrecognized.")
                    
        # 7. Agent Compliance Values Validation
        for agent_name, idx in [("AD Enrollment", ad_idx), ("BitLocker", bitlocker_idx), ("Zscaler vpn", zscaler_idx), ("Nessus agent", nessus_idx), ("SentinelOne edr", s1_idx), ("SCCM patch", sccm_idx)]:
            if idx != -1:
                val = str(row[idx]).strip().lower()
                if val:
                    # check version/phrases and fallback exact keywords
                    is_valid = (re.search(r'\d+\.\d+', val) or re.match(r'^v\d+', val) or
                                val in {"compliant", "non_compliant", "non compliant", "installed", "missing", "yes", "no", "true", "false", "1", "0", "active", "inactive", "disabled", "fail", "failed", "non-compliant", "offline", "critical", "enrolled", "active_enrollment", "active enrollment", "success", "ok", "pass", "passed", "on", "enabled", "running", "secured", "secure", "monitored", "up-to-date", "up to date", "encrypted", "encryption", "protected", "error", "not enrolled", "not_enrolled", "unenrolled", "out of date", "out_of_date", "outdated", "vulnerable",
                                        "trusted", "trusted network", "trusted_network", "trusted-network", "established", "tunnel established", "machine tunnel", "machine_tunnel", "machine_tunnel_active", "machine tunnel active", "joined", "domain joined", "domain_joined", "domain-joined", "machine joined", "machine_joined", "aes", "aes-128", "aes-256", "aes128", "aes256", "xts-aes", "xts_aes", "scanned", "clean", "safe", "completed", "scan completed", "healthy", "no vulnerabilities", "no_vulnerabilities", "patched", "fully patched", "updated", "fully updated", "current", "latest"})
                    if not is_valid:
                        # Split by word and check if it contains any known standard word
                        words = re.split(r'[^a-z0-9]+', val)
                        has_standard_words = any(w in {"compliant", "installed", "yes", "true", "active", "enrolled", "success", "ok", "pass", "passed", "on", "enabled", "running", "secured", "secure", "monitored", "encrypted", "encryption", "protected", "connected", "online", "registered", "joined", "trusted", "established", "scanned", "clean", "safe", "completed", "healthy", "patched", "updated", "current", "latest", "aes", "xts", "non", "not", "un", "off", "fail", "failed", "inactive", "disconnected", "disabled", "outdated", "vulnerable", "error", "critical", "missing", "unreported", "offline", "no", "none"} for w in words)
                        if not has_standard_words:
                            warnings.append(f"Row {r_idx}: Compliance field '{agent_name}' value '{row[idx]}' contains non-standard text.")
                    
    return {
        "warnings": warnings,
        "errors": errors
    }


# ==============================================================================
# ALIGNMENT DATA NORMALIZATION
# ==============================================================================

def normalize_value(val):
    """Strip all non-alphanumeric characters and lowercase for key matching."""
    if val is None:
        return ""
    val_str = str(val).strip()
    val_low = val_str.lower()
    if val_low in ["disabled", "unknown", "none", "not available", "to be filled by o.e.m.", "-", "outdated", "unreported"]:
        return ""
    return re.sub(r'[^a-zA-Z0-9]', '', val_str).lower()

def norm_mac_list(val):
    """Extracts and normalizes all MAC addresses found in a string."""
    if not val:
        return []
    macs = re.findall(r'[0-9a-fA-F]{2}[:.-][0-9a-fA-F]{2}[:.-][0-9a-fA-F]{2}[:.-][0-9a-fA-F]{2}[:.-][0-9a-fA-F]{2}[:.-][0-9a-fA-F]{2}', str(val))
    return [m.lower().replace('.', ':').replace('-', ':') for m in macs]

def get_col_indices(headers, filename=None):
    """
    Extracts name, serial, and MAC columns from headers based on common naming patterns.
    """
    h_low = [str(h).lower().strip() for h in headers]
    name_keywords = ["devicename", "hostname", "device", "host", "name", "computer", "machine", "system"]
    
    is_zscaler = False
    if filename:
        fn_low = str(filename).lower()
        if "zscaler" in fn_low or "zscalar" in fn_low or "zscalr" in fn_low or "vpn" in fn_low:
            is_zscaler = True
            
    if is_zscaler:
        serial_keywords = ["serialnumber", "serial", "s/n", "sn", "uuid", "udid", "externalid", "external device id", "service tag", "servicetag", "tag", "asset tag", "assettag"]
    else:
        serial_keywords = ["serialnumber", "serial", "s/n", "sn", "uuid", "externalid", "external device id", "service tag", "servicetag", "tag", "asset tag", "assettag"]
        
    mac_keywords = ["macaddress", "mac", "physical", "ethernet", "hardware"]
    
    def find_indices(keywords):
        indices = []
        for idx, h in enumerate(h_low):
            matched = False
            for kw in keywords:
                if len(kw) <= 3:
                    words = re.split(r'[^a-z0-9]+', h)
                    if kw in words:
                        matched = True
                        break
                else:
                    if kw in h:
                        matched = True
                        break
            if matched:
                indices.append(idx)
        return indices
        
    return find_indices(name_keywords), find_indices(serial_keywords), find_indices(mac_keywords)


# ==============================================================================
# RECONCILIATION ENGINE (O(1) Multi-Sheet Alignment)
# ==============================================================================

def row_matches(prim_row, prim_meta, sec_row, sec_meta):
    """
    Returns True if a primary corporate row matches a secondary agent row on
    (a) unique key value, (b) hostname, (c) serial number, or (d) MAC address.
    """
    prim_key_val = normalize_value(prim_row[prim_meta['key_idx']]) if prim_meta['key_idx'] < len(prim_row) else ""
    sec_key_val = normalize_value(sec_row[sec_meta['key_idx']]) if sec_meta['key_idx'] < len(sec_row) else ""
    if prim_key_val and prim_key_val == sec_key_val:
        return True
        
    # Check matching hostnames
    for p_idx in prim_meta.get('name_indices', []):
        for s_idx in sec_meta.get('name_indices', []):
            if p_idx < len(prim_row) and s_idx < len(sec_row):
                p_name = normalize_value(prim_row[p_idx])
                s_name = normalize_value(sec_row[s_idx])
                if p_name and p_name == s_name:
                    return True
                    
    # Check matching serials
    for p_idx in prim_meta.get('serial_indices', []):
        for s_idx in sec_meta.get('serial_indices', []):
            if p_idx < len(prim_row) and s_idx < len(sec_row):
                p_serial = normalize_value(prim_row[p_idx])
                s_serial = normalize_value(sec_row[s_idx])
                if p_serial and p_serial == s_serial:
                    return True
                    
    # Check matching MAC addresses
    for p_idx in prim_meta.get('mac_indices', []):
        for s_idx in sec_meta.get('mac_indices', []):
            if p_idx < len(prim_row) and s_idx < len(sec_row):
                p_mac_val = prim_row[p_idx]
                s_mac_val = sec_row[s_idx]
                p_macs = norm_mac_list(p_mac_val)
                s_macs = norm_mac_list(s_mac_val)
                if p_macs and s_macs:
                    if set(p_macs) & set(s_macs):
                        return True
                        
    return False

def reconcile_sheets_data(primary_sheet, secondary_sheets):
    """
    Primary reconciliation alignment engine.
    Matches devices in the Primary Corporate Directory against multiple secondary telemetry datasets.
    
    Returns a dictionary structured as follows:
    - matches: Devices successfully aligned across datasets.
    - gaps: Devices in the Corporate Directory but missing from telemetry.
    - rogues: Telemetry entries that do not map to any Corporate Directory device.
    """
    primary_key_idx = primary_sheet["keyIdx"]
    primary_headers = primary_sheet["headers"]
    primary_rows = primary_sheet["rows"]
    primary_filename = primary_sheet.get("filename", "")
    
    # Step 1: Pre-process and map Primary Directory column indexes
    prim_name_indices, prim_serial_indices, prim_mac_indices = get_col_indices(primary_headers, primary_filename)
    prim_meta = {
        'key_idx': primary_key_idx,
        'name_indices': prim_name_indices,
        'serial_indices': prim_serial_indices,
        'mac_indices': prim_mac_indices
    }
    
    # Step 2: Index all Secondary sheets to create maps for O(1) matching lookups
    sec_sheets_processed = []
    for sheet in secondary_sheets:
        key_idx = sheet["keyIdx"]
        headers = sheet["headers"]
        rows = sheet["rows"]
        filename = sheet.get("filename", "")
        
        valid_rows = []
        for r in rows:
            if r and not all(str(c).strip() == "" for c in r):
                valid_rows.append(r)
                
        name_indices, serial_indices, mac_indices = get_col_indices(headers, filename)
        
        # Pre-build lookup maps for O(1) matching
        key_map = {}
        name_map = {}
        serial_map = {}
        mac_map = {}
        
        for r_idx, s_row in enumerate(valid_rows):
            # 1. Match Key
            sec_key_val = normalize_value(s_row[key_idx]) if key_idx < len(s_row) else ""
            if sec_key_val:
                key_map.setdefault(sec_key_val, []).append(r_idx)
                
            # 2. Hostnames
            for s_idx in name_indices:
                if s_idx < len(s_row):
                    s_name = normalize_value(s_row[s_idx])
                    if s_name:
                        name_map.setdefault(s_name, []).append(r_idx)
                        
            # 3. Serials
            for s_idx in serial_indices:
                if s_idx < len(s_row):
                    s_serial = normalize_value(s_row[s_idx])
                    if s_serial:
                        serial_map.setdefault(s_serial, []).append(r_idx)
                        
            # 4. MAC Addresses
            for s_idx in mac_indices:
                if s_idx < len(s_row):
                    s_mac_val = s_row[s_idx]
                    s_macs = norm_mac_list(s_mac_val)
                    for sm in s_macs:
                        if sm:
                            mac_map.setdefault(sm, []).append(r_idx)
                            
        sec_meta = {
            'key_idx': key_idx,
            'name_indices': name_indices,
            'serial_indices': serial_indices,
            'mac_indices': mac_indices
        }
        
        sec_sheets_processed.append({
            "filename": sheet["filename"],
            "headers": headers,
            "rows": valid_rows,
            "meta": sec_meta,
            "key_map": key_map,
            "name_map": name_map,
            "serial_map": serial_map,
            "mac_map": mac_map,
            "matched_indices": set()
        })
        
    matches = []
    gaps = []
    
    import random
    
    # Step 3: Match each Corporate Directory entry against Telemetries
    for p_row_idx, p_row in enumerate(primary_rows):
        if not p_row or all(str(c).strip() == "" for c in p_row):
            continue
            
        raw_name = str(p_row[primary_key_idx]).strip() if primary_key_idx < len(p_row) else f"Device-{p_row_idx + 1}"
        
        present_in_sheets = []
        missing_in_sheets = []
        merged_properties = []
        
        # Pull clean Corporate Directory custom properties
        for idx, h in enumerate(primary_headers):
            if idx != primary_key_idx:
                val = str(p_row[idx]).strip() if idx < len(p_row) else ""
                merged_properties.append({
                    "source": primary_sheet["filename"],
                    "sheetRole": "Primary",
                    "property": h,
                    "value": val if val else "-"
                })
                
        # Query secondary telemetry lookup maps for matches
        for sec in sec_sheets_processed:
            matched_row = None
            matched_r_idx = -1
            
            # (a) Match unique key
            prim_key_val = normalize_value(p_row[primary_key_idx]) if primary_key_idx < len(p_row) else ""
            if prim_key_val and prim_key_val in sec["key_map"]:
                candidates = sec["key_map"][prim_key_val]
                if candidates:
                    matched_r_idx = candidates[0]
                    
            # (b) Match hostname
            if matched_r_idx == -1 and prim_name_indices:
                for p_idx in prim_name_indices:
                    if p_idx < len(p_row):
                        p_name = normalize_value(p_row[p_idx])
                        if p_name and p_name in sec["name_map"]:
                            candidates = sec["name_map"][p_name]
                            if candidates:
                                matched_r_idx = candidates[0]
                                break
                                
            # (c) Match Serial Number
            if matched_r_idx == -1 and prim_serial_indices:
                for p_idx in prim_serial_indices:
                    if p_idx < len(p_row):
                        p_serial = normalize_value(p_row[p_idx])
                        if p_serial and p_serial in sec["serial_map"]:
                            candidates = sec["serial_map"][p_serial]
                            if candidates:
                                matched_r_idx = candidates[0]
                                break
                                
            # (d) Match MAC address
            if matched_r_idx == -1 and prim_mac_indices:
                for p_idx in prim_mac_indices:
                    if p_idx < len(p_row):
                        p_mac_val = p_row[p_idx]
                        p_macs = norm_mac_list(p_mac_val)
                        for pm in p_macs:
                            if pm and pm in sec["mac_map"]:
                                candidates = sec["mac_map"][pm]
                                if candidates:
                                    matched_r_idx = candidates[0]
                                    break
                    if matched_r_idx != -1:
                        break
                        
            if matched_r_idx != -1:
                matched_row = sec["rows"][matched_r_idx]
                sec["matched_indices"].add(matched_r_idx)
                
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
        
        # Categorize aligned devices as Gaps (missing telemetry) or Matches
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
            
    # Step 4: Any telemetry records left unclaimed are marked as Rogue Assets
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
