from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Dict, Any
import json
from datetime import datetime
from backend.app.database import get_db
from backend.app.scanners.automated_checks import run_http_header_audits
from backend.app.scanners.zap_client import ZAPClient
from backend.app.evidence import services as evidence_services

router = APIRouter(prefix="/api/scanners", tags=["Automated Web Scanners"])

class ScanRequest(BaseModel):
    target_url: str
    assessment_id: int

@router.post("/audit")
def run_security_audit(request: ScanRequest, db: Session = Depends(get_db)):
    """
    Triggers both HTTP header scans and OWASP ZAP active vulnerability audits on the target URL.
    Saves the results as cryptographically signed evidence records bound to the assessment session.
    """
    target = request.target_url
    assessment_id = request.assessment_id
    
    # 1. Run HTTP Header Checks
    http_results = run_http_header_audits(target)
    if not http_results.get("success", True):
        raise HTTPException(
            status_code=400, 
            detail=f"HTTP Audits failed: {http_results.get('error')}"
        )
        
    # 2. Run ZAP Scan
    zap = ZAPClient()
    zap_results = zap.perform_full_audit(target)
    if not zap_results.get("success", True):
        raise HTTPException(
            status_code=400, 
            detail=f"ZAP Audits failed: {zap_results.get('error')}"
        )

    # 3. Store HTTP Check as secure evidence
    collected_at_str = datetime.utcnow().isoformat()
    # Serialize the reports to json text
    # Standardize the format so the mappings interpreter can match patterns easily
    http_log_content = []
    for code, audit in http_results["report"].items():
        status_str = "PASS" if audit["passed"] else "FAIL"
        http_log_content.append(f"{code} Status: {status_str} Details: {audit['details']}")
    
    http_raw_data = "\n".join(http_log_content)
    
    evidence_services.create_evidence(
        db=db,
        source="HTTP_CHECK",
        raw_data=http_raw_data,
        collected_at=collected_at_str,
        assessment_id=assessment_id
    )
    
    # 4. Store ZAP Scan as secure evidence
    zap_log_content = []
    for alert in zap_results["alerts"]:
        zap_log_content.append(
            f"ZAP Alert: {alert['alert']} Severity: {alert['risk']} Vulnerability Details: {alert['description']}"
        )
    # If ZAP found any High/Critical, represent it in the log
    if zap_results["summary"]["high"] > 0:
        zap_log_content.append("ZAP Status: High Vulnerability detected.")
        
    zap_raw_data = "\n".join(zap_log_content)
    
    evidence_services.create_evidence(
        db=db,
        source="ZAP",
        raw_data=zap_raw_data,
        collected_at=collected_at_str,
        assessment_id=assessment_id
    )

    return {
        "success": True,
        "target_url": target,
        "assessment_id": assessment_id,
        "scans": {
            "http_headers": http_results,
            "zap_vulnerabilities": zap_results
        }
    }
