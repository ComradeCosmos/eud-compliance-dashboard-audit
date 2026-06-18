import unittest
import sys
import os

# Ensure the project root and backend are in path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.app.security import (
    is_blacklisted_ip, 
    validate_url_for_ssrf, 
    calculate_evidence_hash, 
    verify_evidence_integrity
)

class TestSecurityControls(unittest.TestCase):
    def test_blacklisted_ips(self):
        # Private and link-local ranges should be blacklisted
        self.assertTrue(is_blacklisted_ip("127.0.0.1"))
        self.assertTrue(is_blacklisted_ip("10.0.0.1"))
        self.assertTrue(is_blacklisted_ip("192.168.1.50"))
        self.assertTrue(is_blacklisted_ip("169.254.169.254"))
        self.assertTrue(is_blacklisted_ip("0.0.0.0"))
        self.assertTrue(is_blacklisted_ip("::1"))
        
        # Public IPs should NOT be blacklisted
        self.assertFalse(is_blacklisted_ip("8.8.8.8"))
        self.assertFalse(is_blacklisted_ip("142.250.190.46"))

    def test_ssrf_url_validation(self):
        # Localhost should resolve and be blocked
        is_valid, ip = validate_url_for_ssrf("http://localhost:8000")
        self.assertFalse(is_valid)
        
        # Invalid domains should be blocked
        is_valid, ip = validate_url_for_ssrf("http://nonexistent-dev-domain.invalid")
        self.assertFalse(is_valid)

    def test_evidence_cryptographic_signatures(self):
        raw_log = "User admin logged in from 10.0.0.5"
        assessment_id = "1"
        collected_at = "2026-06-18T09:30:00"
        
        # Generate signature
        sig = calculate_evidence_hash(raw_log, assessment_id, collected_at)
        self.assertEqual(len(sig), 64)  # SHA-256 is 64 chars hex
        
        # Verify valid signature
        self.assertTrue(verify_evidence_integrity(raw_log, assessment_id, collected_at, sig))
        
        # Verify tampered data fails signature verification
        self.assertFalse(verify_evidence_integrity(raw_log + " modified", assessment_id, collected_at, sig))
        self.assertFalse(verify_evidence_integrity(raw_log, "2", collected_at, sig))

if __name__ == "__main__":
    unittest.main()
