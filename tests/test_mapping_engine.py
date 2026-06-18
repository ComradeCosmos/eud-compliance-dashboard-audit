import unittest
import sys
import os

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.app.checklist.services import evaluate_rule

class TestMappingEngine(unittest.TestCase):
    def test_rule_contains(self):
        rule = {"condition": "contains", "pattern": "Strict-Transport-Security", "fail_msg": "Missing HSTS"}
        
        passed, details = evaluate_rule(rule, "Strict-Transport-Security: max-age=31536000")
        self.assertTrue(passed)
        
        passed, details = evaluate_rule(rule, "Server: Apache")
        self.assertFalse(passed)

    def test_rule_not_contains(self):
        rule = {"condition": "not_contains", "pattern": "default-src *", "fail_msg": "Wildcard CSP"}
        
        passed, details = evaluate_rule(rule, "default-src 'self'")
        self.assertTrue(passed)
        
        passed, details = evaluate_rule(rule, "default-src *; script-src 'self'")
        self.assertFalse(passed)

    def test_rule_regex_match(self):
        rule = {
            "condition": "regex_match", 
            "pattern": r"(?i)strict-transport-security:\s*max-age=(\d+)", 
            "min_value": 31536000, 
            "fail_msg": "Invalid HSTS age"
        }
        
        # Valid age >= 31536000
        passed, details = evaluate_rule(rule, "Strict-Transport-Security: max-age=31536000")
        self.assertTrue(passed)
        
        passed, details = evaluate_rule(rule, "strict-transport-security:max-age=63072000; includeSubDomains")
        self.assertTrue(passed)
        
        # Invalid age < 31536000
        passed, details = evaluate_rule(rule, "Strict-Transport-Security: max-age=15768000")
        self.assertFalse(passed)
        
        # Header missing entirely
        passed, details = evaluate_rule(rule, "Cache-Control: no-cache")
        self.assertFalse(passed)

if __name__ == "__main__":
    unittest.main()
