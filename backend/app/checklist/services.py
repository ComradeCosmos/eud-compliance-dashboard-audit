import os
import re
import yaml
from sqlalchemy.orm import Session
from typing import List, Dict, Any, Optional
from backend.app.database import get_db
from backend.app.assessment.models import Assessment, Finding
from backend.app.evidence.models import Evidence
from backend.app.assessment import services as assessment_services

# Paths to configurations
CUR_DIR = os.path.dirname(os.path.abspath(__file__))
CHECKLIST_PATH = os.path.join(CUR_DIR, "checklist.yaml")
MAPPINGS_PATH = os.path.join(CUR_DIR, "mappings.yaml")

def load_yaml(path: str) -> Dict[str, Any]:
    with open(path, "r") as f:
        return yaml.safe_load(f)

def get_checklist_controls() -> List[Dict[str, Any]]:
    """Loads and returns all 15 predefined audit controls."""
    data = load_yaml(CHECKLIST_PATH)
    return data.get("controls", [])

def get_mapping_rules() -> List[Dict[str, Any]]:
    """Loads and returns all mapping interpreter rules."""
    data = load_yaml(MAPPINGS_PATH)
    return data.get("rules", [])

def evaluate_rule(rule: Dict[str, Any], raw_data: str) -> tuple[bool, str]:
    """
    Evaluates a single mapping rule against the raw evidence log.
    Returns (passed, details).
    """
    condition = rule.get("condition")
    pattern = rule.get("pattern")
    
    if not pattern:
        return True, "No pattern defined. Defaulting to PASS."

    if condition == "contains":
        passed = pattern in raw_data
        details = "Pattern found." if passed else f"Failed check: {rule.get('fail_msg')}"
        return passed, details
        
    elif condition == "not_contains":
        passed = pattern not in raw_data
        details = "Pattern not found." if passed else f"Failed check: {rule.get('fail_msg')}"
        return passed, details
        
    elif condition == "regex_match":
        match = re.search(pattern, raw_data)
        if not match:
            return False, f"Failed check: {rule.get('fail_msg')}"
            
        # Optional check for min_value if regex captures a numeric group
        min_value = rule.get("min_value")
        if min_value is not None and match.groups():
            try:
                val = int(match.group(1))
                if val < min_value:
                    return False, f"Captured value {val} is below minimum requirement of {min_value}."
                return True, f"Passed: Captured value {val} satisfies >= {min_value} requirement."
            except (ValueError, IndexError):
                return False, f"Failed to extract integer from match group for HSTS validation."
                
        return True, "Regex pattern matched successfully."
        
    return True, "Unknown condition. Defaulting to PASS."

def evaluate_evidence_and_upsert_findings(db: Session, assessment_id: int) -> List[Finding]:
    """
    Runs checklist mapping evaluations for an assessment session.
    Ensures all 15 controls are instantiated.
    """
    assessment = assessment_services.get_assessment(db, assessment_id)
    if not assessment:
        raise ValueError(f"Assessment {assessment_id} not found")
        
    controls = get_checklist_controls()
    rules = get_mapping_rules()
    evidence_list = db.query(Evidence).filter(Evidence.assessment_id == assessment_id).all()
    
    existing_findings = {f.control_code: f for f in db.query(Finding).filter(Finding.assessment_id == assessment_id).all()}
    created_or_updated = []
    
    for ctrl in controls:
        code = ctrl["code"]
        title = ctrl["title"]
        ctrl_type = ctrl["type"]
        severity = ctrl["severity"]
        desc = ctrl["description"]
        rec = ctrl["recommendation"]
        
        # 1. Check if there's a custom rule mapping for this control code
        ctrl_rules = [r for r in rules if r["control_code"] == code]
        
        status = "FAIL"
        details = ""
        matching_evidence_id = None
        
        if ctrl_type == "MANUAL":
            # For manual items, preserve existing status if present, otherwise default to FAIL
            if code in existing_findings:
                status = existing_findings[code].status
                details = existing_findings[code].details or "Preserved auditor manual assessment."
            else:
                status = "FAIL"
                details = "Pending auditor manual checklist verification."
                
        elif not ctrl_rules:
            # If no rule defined, set to FAIL by default unless custom logic applies
            status = "FAIL"
            details = "No automated check rules defined for this control."
            
        else:
            # Evaluate rules against ingested evidence
            rule_evaluations = []
            
            for rule in ctrl_rules:
                source = rule["source"]
                # Find evidence matching the source required by the rule
                matching_evs = [ev for ev in evidence_list if ev.source.upper() == source.upper()]
                
                if not matching_evs:
                    rule_evaluations.append((False, f"Missing evidence log for source '{source}'", None))
                else:
                    # Run rule against each matched evidence log
                    for ev in matching_evs:
                        passed, r_details = evaluate_rule(rule, ev.raw_data)
                        rule_evaluations.append((passed, r_details, ev.id))
            
            # Aggregate results: must pass all rule checks
            if not rule_evaluations:
                status = "FAIL"
                details = "No evidence gathered for automated validation."
            else:
                failed_checks = [r for r in rule_evaluations if not r[0]]
                if failed_checks:
                    status = "FAIL"
                    details = "; ".join([r[1] for r in failed_checks])
                    # Associate with the first failing evidence
                    matching_evidence_id = next((r[2] for r in failed_checks if r[2] is not None), None)
                else:
                    status = "PASS"
                    details = "All automated checks passed."
                    # Associate with first passing evidence
                    matching_evidence_id = next((r[2] for r in rule_evaluations if r[2] is not None), None)

        # Upsert Finding
        if code in existing_findings:
            db_finding = existing_findings[code]
            db_finding.status = status
            db_finding.details = details
            db_finding.evidence_id = matching_evidence_id
            db_finding.recommendation = rec
        else:
            db_finding = Finding(
                assessment_id=assessment_id,
                control_code=code,
                control_title=title,
                severity=severity,
                status=status,
                evidence_id=matching_evidence_id,
                details=details,
                recommendation=rec,
                type=ctrl_type
            )
            db.add(db_finding)
            
        created_or_updated.append(db_finding)
        
    db.commit()
    # Refresh all findings
    for f in created_or_updated:
        db.refresh(f)
        
    return created_or_updated
