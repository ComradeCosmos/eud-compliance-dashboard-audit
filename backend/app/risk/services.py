from sqlalchemy.orm import Session
from backend.app.assessment.models import Assessment, Finding
from backend.app.checklist import services as checklist_services
from backend.app.assessment import services as assessment_services

SEVERITY_WEIGHTS = {
    "HIGH": 10.0,
    "MEDIUM": 5.0,
    "LOW": 2.0
}

def downgrade_severity(base_severity: str, environment: str) -> str:
    """
    Downgrades severity based on environment:
    - Production: Full severity (High, Medium, Low)
    - UAT/QA: Downgrade by 1 level (e.g. HIGH -> MEDIUM, MEDIUM -> LOW)
    - Development: Downgrade by 2 levels (e.g. HIGH -> LOW, MEDIUM -> LOW)
    Never downgrades below LOW for failures.
    """
    severity = base_severity.strip().upper()
    env = environment.strip().capitalize() # Production, Uat, Development
    
    if env == "Production":
        return severity
        
    elif env == "Uat" or env == "Qa":
        if severity == "HIGH":
            return "MEDIUM"
        else:
            return "LOW"
            
    elif env == "Development" or env == "Dev":
        return "LOW"
        
    return severity

def calculate_assessment_risk(db: Session, assessment_id: int) -> float:
    """
    Calculates overall compliance score (0-100) and downgrades finding severities.
    Updates the assessment overall_score and findings' severity in the database.
    """
    assessment = assessment_services.get_assessment(db, assessment_id)
    if not assessment:
        raise ValueError(f"Assessment {assessment_id} not found")
        
    findings = assessment_services.list_findings(db, assessment_id)
    
    # If findings don't exist yet, generate them using checklist evaluator
    if not findings:
        findings = checklist_services.evaluate_evidence_and_upsert_findings(db, assessment_id)
        
    # Get base controls dictionary for base severities
    controls = {c["code"]: c for c in checklist_services.get_checklist_controls()}
    
    total_weight = 0.0
    total_deductions = 0.0
    
    for finding in findings:
        base_ctrl = controls.get(finding.control_code)
        base_severity = base_ctrl["severity"] if base_ctrl else finding.severity
        
        # Apply environment-aware severity downgrade
        effective_severity = downgrade_severity(base_severity, assessment.environment)
        
        # Update finding's effective severity in the DB so it reflects on reports/UI
        finding.severity = effective_severity
        
        weight = SEVERITY_WEIGHTS.get(effective_severity, 2.0)
        total_weight += weight
        
        if finding.status.upper() == "FAIL":
            total_deductions += weight
            
    # Calculate score
    if total_weight > 0:
        score = ((total_weight - total_deductions) / total_weight) * 100.0
    else:
        score = 100.0
        
    # Round to 2 decimal places
    score = round(score, 2)
    
    # Save score to assessment
    assessment.overall_score = score
    assessment.status = "COMPLETED"
    db.commit()
    db.refresh(assessment)
    
    return score
