import unittest
import subprocess
import time
import requests
import sys
import os

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

class TestFastAPIIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Startup the FastAPI app on a non-conflicting port (e.g. 8123)
        cls.server_port = 8123
        cls.base_url = f"http://127.0.0.1:{cls.server_port}"
        
        # Start uvicorn process
        cmd = [
            sys.executable, "-m", "uvicorn", 
            "backend.app.main:app", 
            "--host", "127.0.0.1", 
            "--port", str(cls.server_port),
            "--log-level", "warning"
        ]
        
        cls.log_file = open(os.path.join(PROJECT_ROOT, "tests", "uvicorn_test.log"), "w")
        cls.process = subprocess.Popen(
            cmd,
            stdout=cls.log_file,
            stderr=cls.log_file,
            cwd=PROJECT_ROOT
        )
        
        # Give the server time to boot up
        time.sleep(3.0)

    @classmethod
    def tearDownClass(cls):
        # Forcefully terminate server process on Windows
        cls.process.kill()
        cls.process.wait()
        cls.log_file.close()

    def test_01_static_landing_serving(self):
        # Query root endpoint
        res = requests.get(f"{self.base_url}/")
        self.assertEqual(res.status_code, 200)
        self.assertIn("AM/NS Security Dashboard", res.text)

    def test_02_get_checklist_controls(self):
        # Query controls endpoint
        res = requests.get(f"{self.base_url}/api/checklist/controls")
        self.assertEqual(res.status_code, 200)
        controls = res.json()
        self.assertEqual(len(controls), 10)
        self.assertEqual(controls[0]["code"], "CTRL-001")

    def test_03_create_assessment_and_evaluate(self):
        # 1. Create Assessment
        payload = {"name": "Test SLA Session", "environment": "UAT"}
        res = requests.post(f"{self.base_url}/api/assessments/", json=payload)
        self.assertEqual(res.status_code, 200)
        assessment = res.json()
        self.assertEqual(assessment["name"], "Test SLA Session")
        self.assertEqual(assessment["environment"], "UAT")
        assessment_id = assessment["id"]

        # 2. Trigger rule evaluation (no evidence uploaded yet, should default automated to FAIL)
        res = requests.post(f"{self.base_url}/api/checklist/evaluate/{assessment_id}")
        self.assertEqual(res.status_code, 200)
        findings = res.json()
        self.assertEqual(len(findings), 10)

if __name__ == "__main__":
    unittest.main()
