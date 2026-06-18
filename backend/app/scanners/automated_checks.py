import re
import urllib.parse
from typing import Dict, Any, List
import requests
from backend.app.security import secure_requests_get, validate_url_for_ssrf

def run_http_header_audits(target_url: str) -> Dict[str, Any]:
    """
    Performs secure HTTP checks on the target URL.
    Returns audit details for CTRL-001 through CTRL-008 and CTRL-010.
    """
    report = {}
    
    # 1. Standardize and check initial target
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url
        
    try:
        # Perform secure HTTP GET request (prevents SSRF)
        response = secure_requests_get(target_url, timeout=10)
    except Exception as e:
        return {
            "success": False,
            "error": f"Secure HTTP audit failed to connect or blocked: {str(e)}"
        }
        
    headers = response.headers
    cookies = response.headers.get("Set-Cookie", "")
    html_content = response.text
    
    # --- CTRL-001: HSTS ---
    hsts = headers.get("Strict-Transport-Security", "")
    hsts_ok = False
    if hsts:
        match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
        if match:
            max_age = int(match.group(1))
            if max_age >= 31536000:
                hsts_ok = True
    report["CTRL-001"] = {
        "passed": hsts_ok,
        "details": f"Strict-Transport-Security: {hsts}" if hsts else "HSTS header is missing"
    }
    
    # --- CTRL-002: Secure Cookie Flags ---
    cookie_headers = response.headers.getlist("Set-Cookie") if hasattr(response.headers, "getlist") else [cookies] if cookies else []
    if not cookie_headers and "set-cookie" in headers:
         cookie_headers = [headers["set-cookie"]]
         
    cookies_ok = True
    cookie_details = []
    for cookie in cookie_headers:
        cookie_lower = cookie.lower()
        has_http_only = "httponly" in cookie_lower
        has_secure = "secure" in cookie_lower
        if not (has_http_only and has_secure):
            cookies_ok = False
        cookie_details.append(f"Cookie: {cookie[:50]}... (HttpOnly={has_http_only}, Secure={has_secure})")
        
    report["CTRL-002"] = {
        "passed": cookies_ok if cookie_headers else True,  # If no cookies set, it's PASS
        "details": "; ".join(cookie_details) if cookie_headers else "No cookies set by target"
    }
    
    # --- CTRL-003: Content Security Policy ---
    csp = headers.get("Content-Security-Policy", "")
    csp_ok = False
    if csp:
        if "default-src *" not in csp and "default-src 'none'" in csp or "default-src 'self'" in csp or "default-src" in csp:
            csp_ok = True
    report["CTRL-003"] = {
        "passed": csp_ok,
        "details": f"Content-Security-Policy: {csp}" if csp else "CSP header is missing"
    }
    
    # --- CTRL-004: X-Content-Type-Options ---
    xcto = headers.get("X-Content-Type-Options", "").lower().strip()
    report["CTRL-004"] = {
        "passed": xcto == "nosniff",
        "details": f"X-Content-Type-Options: {xcto}" if xcto else "X-Content-Type-Options header is missing"
    }
    
    # --- CTRL-005: Cache-Control ---
    cc = headers.get("Cache-Control", "").lower()
    cc_ok = "no-store" in cc or "no-cache" in cc
    report["CTRL-005"] = {
        "passed": cc_ok,
        "details": f"Cache-Control: {cc}" if cc else "Cache-Control header is missing"
    }
    
    # --- CTRL-006: Secure Password Forms ---
    # Look for password inputs in the page HTML
    has_password_field = "type=\"password\"" in html_content or "type='password'" in html_content
    password_ok = True
    if has_password_field:
        # Check if there's any form tag using GET or HTTP
        forms = re.findall(r"<form[^>]*>", html_content, re.IGNORECASE)
        for form in forms:
            form_lower = form.lower()
            if "method=\"get\"" in form_lower or "method='get'" in form_lower:
                password_ok = False
            # Check if action submits to HTTP
            action_match = re.search(r"action=[\"'](http://[^\"']+)[\"']", form, re.IGNORECASE)
            if action_match:
                password_ok = False
    report["CTRL-006"] = {
        "passed": password_ok,
        "details": "Password fields found in HTML with POST/HTTPS forms" if has_password_field and password_ok 
                   else "Insecure form configuration found" if not password_ok 
                   else "No password input forms detected on page"
    }
    
    # --- CTRL-007: Cookie Path Restriction ---
    path_ok = True
    for cookie in cookie_headers:
        if "path=" not in cookie.lower():
            path_ok = False
    report["CTRL-007"] = {
        "passed": path_ok if cookie_headers else True,
        "details": "All cookies have path restrictions" if path_ok and cookie_headers else "Some cookies lack path restrictions" if not path_ok else "No cookies set by target"
    }
    
    # --- CTRL-008: Server Banner Disclosure ---
    server = headers.get("Server", "")
    powered_by = headers.get("X-Powered-By", "")
    
    # Fail if they leak version numbers (e.g. Apache/2.4.41 or Nginx/1.18.0)
    server_disclosed = False
    if server and re.search(r"\d+\.\d+", server):
        server_disclosed = True
    if powered_by and re.search(r"\d+\.\d+", powered_by):
        server_disclosed = True
        
    report["CTRL-008"] = {
        "passed": not server_disclosed,
        "details": f"Server: {server} | X-Powered-By: {powered_by}" if (server or powered_by) else "No server banners disclosed"
    }
    
    # --- CTRL-010: Unencrypted HTTP Fallback (HTTP -> HTTPS Redirect check) ---
    fallback_ok = False
    # If standard URL is https, test its http counterpart redirect
    if target_url.startswith("https://"):
        http_url = target_url.replace("https://", "http://")
        try:
            # We want to verify that GET on http:// resolves with redirect to https://
            r = secure_requests_get(http_url, timeout=5)
            # If the final URL has https://, the redirect succeeded!
            if r.url.startswith("https://"):
                fallback_ok = True
        except Exception:
            # If connection refused on http but https works, it can be acceptable, or fail
            fallback_ok = False
    report["CTRL-010"] = {
        "passed": fallback_ok,
        "details": "Redirect to HTTPS active" if fallback_ok else "No redirect to HTTPS detected"
    }
    
    return {
        "success": True,
        "url": target_url,
        "resolved_ip": response.url, # Contains final redirected URL/IP information
        "report": report
    }
