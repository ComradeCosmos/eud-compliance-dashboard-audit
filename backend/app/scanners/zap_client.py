import requests
from typing import Dict, Any, List
from backend.app.config import settings
from backend.app.security import validate_url_for_ssrf

class ZAPClient:
    def __init__(self, api_url: str = settings.ZAP_API_URL, api_key: str = settings.ZAP_API_KEY):
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.simulation_mode = settings.ZAP_SIMULATION_MODE

    def run_spider(self, target_url: str) -> str:
        """Triggers ZAP spider scan on target URL and returns scan ID."""
        if self.simulation_mode:
            return "mock-spider-1001"
            
        url = f"{self.api_url}/JSON/spider/action/scan/"
        params = {"url": target_url, "apikey": self.api_key}
        response = requests.get(url, params=params)
        response.raise_for_status()
        return response.json().get("scan", "")

    def run_active_scan(self, target_url: str) -> str:
        """Triggers ZAP active scanner and returns scan ID."""
        if self.simulation_mode:
            return "mock-ascan-2002"
            
        url = f"{self.api_url}/JSON/ascan/action/scan/"
        params = {"url": target_url, "apikey": self.api_key}
        response = requests.get(url, params=params)
        response.raise_for_status()
        return response.json().get("scan", "")

    def get_alerts(self, target_url: str) -> List[Dict[str, Any]]:
        """Retrieves security alerts identified by ZAP."""
        if self.simulation_mode:
            # Simulated vulnerability scan response
            return [
                {
                    "alert": "Content Security Policy (CSP) Header Not Set",
                    "risk": "Medium",
                    "confidence": "High",
                    "description": "CSP header is missing from web request."
                },
                {
                    "alert": "Missing Anti-Clickjacking Header",
                    "risk": "Medium",
                    "confidence": "Medium",
                    "description": "X-Frame-Options header not found."
                },
                {
                    "alert": "X-Content-Type-Options Header Missing",
                    "risk": "Low",
                    "confidence": "High",
                    "description": "Nosniff directive not present in response headers."
                }
            ]

        url = f"{self.api_url}/JSON/core/view/alerts/"
        params = {"baseurl": target_url, "apikey": self.api_key}
        response = requests.get(url, params=params)
        response.raise_for_status()
        return response.json().get("alerts", [])

    def perform_full_audit(self, target_url: str) -> Dict[str, Any]:
        """
        Runs full spider + vulnerability checks (with SSRF protection).
        """
        # SSRF checks
        is_valid, ip = validate_url_for_ssrf(target_url)
        if not is_valid:
            return {
                "success": False,
                "error": f"Target blocked by SSRF Guard (Resolved IP: {ip})"
            }

        try:
            spider_id = self.run_spider(target_url)
            ascan_id = self.run_active_scan(target_url)
            alerts = self.get_alerts(target_url)
            
            # Count risks
            high_count = sum(1 for a in alerts if a.get("risk") == "High")
            medium_count = sum(1 for a in alerts if a.get("risk") == "Medium")
            low_count = sum(1 for a in alerts if a.get("risk") == "Low")
            
            return {
                "success": True,
                "target": target_url,
                "simulation": self.simulation_mode,
                "spider_scan_id": spider_id,
                "active_scan_id": ascan_id,
                "alerts": alerts,
                "summary": {
                    "high": high_count,
                    "medium": medium_count,
                    "low": low_count
                }
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"ZAP Scan execution failed: {str(e)}"
            }
