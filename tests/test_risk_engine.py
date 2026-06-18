import unittest
import sys
import os

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.app.risk.services import downgrade_severity

class TestRiskEngine(unittest.TestCase):
    def test_production_environment(self):
        # Production should maintain original severities
        self.assertEqual(downgrade_severity("HIGH", "Production"), "HIGH")
        self.assertEqual(downgrade_severity("MEDIUM", "Production"), "MEDIUM")
        self.assertEqual(downgrade_severity("LOW", "Production"), "LOW")

    def test_uat_environment(self):
        # UAT/QA should downgrade by 1 level
        self.assertEqual(downgrade_severity("HIGH", "UAT"), "MEDIUM")
        self.assertEqual(downgrade_severity("MEDIUM", "UAT"), "LOW")
        self.assertEqual(downgrade_severity("LOW", "UAT"), "LOW")  # Never below LOW

    def test_development_environment(self):
        # Development should downgrade by 2 levels (everything goes to LOW)
        self.assertEqual(downgrade_severity("HIGH", "Development"), "LOW")
        self.assertEqual(downgrade_severity("MEDIUM", "Development"), "LOW")
        self.assertEqual(downgrade_severity("LOW", "Development"), "LOW")

if __name__ == "__main__":
    unittest.main()
