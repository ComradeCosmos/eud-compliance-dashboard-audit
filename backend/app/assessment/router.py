from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from backend.app.database import get_db
from backend.app.assessment.schemas import (
    AssessmentCreate, AssessmentUpdate, AssessmentResponse, AssessmentDetailResponse,
    FindingCreate, FindingResponse
)
from backend.app.assessment import services as assessment_services

router = APIRouter(prefix="/api/assessments", tags=["Assessments & Findings"])

@router.post("/", response_model=AssessmentResponse)
def create_assessment(assessment_in: AssessmentCreate, db: Session = Depends(get_db)):
    """Creates a new compliance assessment session."""
    return assessment_services.create_assessment(db, assessment_in)

@router.get("/", response_model=List[AssessmentResponse])
def get_assessments(db: Session = Depends(get_db)):
    """Lists all assessment sessions."""
    return assessment_services.list_assessments(db)

@router.get("/{assessment_id}", response_model=AssessmentDetailResponse)
def get_assessment_details(assessment_id: int, db: Session = Depends(get_db)):
    """Retrieves full details of an assessment, including evidence logs and evaluated findings."""
    assessment = assessment_services.get_assessment(db, assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return assessment

@router.delete("/{assessment_id}")
def delete_assessment(assessment_id: int, db: Session = Depends(get_db)):
    """Deletes an assessment session."""
    success = assessment_services.delete_assessment(db, assessment_id)
    if not success:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return {"success": True, "message": "Assessment deleted successfully"}

@router.put("/{assessment_id}", response_model=AssessmentResponse)
def update_assessment(assessment_id: int, assessment_update: AssessmentUpdate, db: Session = Depends(get_db)):
    """Updates an assessment session (e.g. environment or status)."""
    assessment = assessment_services.update_assessment(db, assessment_id, assessment_update)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return assessment

@router.post("/{assessment_id}/findings", response_model=FindingResponse)
def create_finding(assessment_id: int, finding_in: FindingCreate, db: Session = Depends(get_db)):
    """Manually registers an audit finding for an assessment."""
    if finding_in.assessment_id != assessment_id:
        raise HTTPException(status_code=400, detail="Path assessment_id must match body assessment_id")
    return assessment_services.create_finding(db, finding_in)

@router.get("/{assessment_id}/findings", response_model=List[FindingResponse])
def get_assessment_findings(assessment_id: int, db: Session = Depends(get_db)):
    """Retrieves all findings for a given assessment session."""
    return assessment_services.list_findings(db, assessment_id)

@router.put("/findings/{finding_id}", response_model=FindingResponse)
def update_finding(
    finding_id: int, 
    status: str = Query(..., description="PASS or FAIL"),
    details: Optional[str] = Query(None, description="Details or explanations for the status"),
    recommendation: Optional[str] = Query(None, description="Remediation steps"),
    db: Session = Depends(get_db)
):
    """
    Updates the evaluation status of a specific control finding (useful for auditor manual checklists).
    """
    if status not in ("PASS", "FAIL"):
        raise HTTPException(status_code=400, detail="Status must be either PASS or FAIL")
        
    finding = assessment_services.update_finding(
        db=db,
        finding_id=finding_id,
        status=status,
        details=details,
        recommendation=recommendation
    )
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding
