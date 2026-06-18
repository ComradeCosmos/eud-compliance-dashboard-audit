import socket
import urllib.parse
import ipaddress
import hashlib
import requests
from typing import Tuple, Optional

def get_ip_from_url(url: str) -> str:
    """Extracts hostname from URL and resolves it to an IP address."""
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Invalid URL: hostname not found")
    try:
        # Resolve hostname to IP
        ip = socket.gethostbyname(hostname)
        return ip
    except socket.gaierror as e:
        raise ValueError(f"Could not resolve hostname {hostname}: {e}")

def is_blacklisted_ip(ip_str: str) -> bool:
    """Checks if the resolved IP address is in a private, loopback, or link-local range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        # Check standard private/reserved subnets using ipaddress module properties
        return (
            ip.is_private or
            ip.is_loopback or
            ip.is_link_local or
            ip.is_reserved or
            ip.is_multicast or
            ip.is_unspecified
        )
    except ValueError:
        return True  # If invalid IP, treat as blacklisted for safety

def validate_url_for_ssrf(url: str) -> Tuple[bool, Optional[str]]:
    """
    Validates a URL to prevent SSRF.
    Returns (is_valid, resolved_ip).
    """
    try:
        ip = get_ip_from_url(url)
        if is_blacklisted_ip(ip):
            return False, ip
        return True, ip
    except Exception:
        return False, None

def secure_requests_get(url: str, **kwargs) -> requests.Response:
    """
    Executes a requests.get securely by validating the initial URL and any redirect locations.
    Only allows redirects if the redirected URL is also validated.
    """
    current_url = url
    max_redirects = kwargs.pop("max_redirects", 5)
    
    # Force redirects to False so we can manually validate them
    kwargs["allow_redirects"] = False
    
    for _ in range(max_redirects + 1):
        is_valid, ip = validate_url_for_ssrf(current_url)
        if not is_valid:
            raise requests.exceptions.RequestException(
                f"Blocked SSRF target URL: {current_url} (Resolved IP: {ip})"
            )
        
        response = requests.get(current_url, **kwargs)
        
        # If it's a redirect, manually inspect Location header
        if response.status_code in (301, 302, 303, 307, 308):
            redirect_url = response.headers.get("Location")
            if not redirect_url:
                return response
            
            # Resolve relative URLs
            redirect_url = urllib.parse.urljoin(current_url, redirect_url)
            current_url = redirect_url
        else:
            return response
            
    raise requests.exceptions.TooManyRedirects("Exceeded maximum secure redirects limit")

def calculate_evidence_hash(raw_data: str, assessment_id: str, collected_at: str) -> str:
    """
    Calculates SHA-256 signature for audit evidence: SHA-256(raw_data + assessment_id + collected_at)
    """
    hasher = hashlib.sha256()
    payload = f"{raw_data}{assessment_id}{collected_at}".encode('utf-8')
    hasher.update(payload)
    return hasher.hexdigest()

def verify_evidence_integrity(raw_data: str, assessment_id: str, collected_at: str, expected_hash: str) -> bool:
    """
    Verifies that the raw_data + metadata matches the expected_hash.
    """
    actual_hash = calculate_evidence_hash(raw_data, assessment_id, collected_at)
    return actual_hash == expected_hash
