from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Dict, Any
from backend.app.database import get_db
from backend.app.assessment.schemas import FindingResponse
from backend.app.checklist import services as checklist_services

router = APIRouter(prefix="/api/checklist", tags=["Checklist & Mappings Engine"])

@router.get("/controls", response_model=List[Dict[str, Any]])
def get_controls():
    """Retrieves the 15 predefined security compliance controls."""
    return checklist_services.get_checklist_controls()

@router.get("/mappings", response_model=List[Dict[str, Any]])
def get_mappings():
    """Retrieves the YAML mapping rules used by the interpreter engine."""
    return checklist_services.get_mapping_rules()

@router.post("/evaluate/{assessment_id}", response_model=List[FindingResponse])
def evaluate_assessment(assessment_id: int, db: Session = Depends(get_db)):
    """
    Triggers the YAML mappings evaluation interpreter for the specified assessment.
    Parses and matches SIEM logs and active scans to the 15 security controls.
    """
    try:
        findings = checklist_services.evaluate_evidence_and_upsert_findings(db, assessment_id)
        return findings
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Checklist evaluation failed: {str(e)}")
