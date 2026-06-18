from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.assessment.schemas import AssessmentResponse
from backend.app.risk import services as risk_services

router = APIRouter(prefix="/api/risk", tags=["Unified Risk Engine"])

@router.post("/calculate/{assessment_id}", response_model=AssessmentResponse)
def calculate_risk_score(assessment_id: int, db: Session = Depends(get_db)):
    """
    Triggers the centralized environment-aware Risk Engine calculations.
    Evaluates findings, applies severity level downgrades, and updates the overall compliance score.
    """
    try:
        risk_services.calculate_assessment_risk(db, assessment_id)
        # Reload and return assessment
        from backend.app.assessment import services as assessment_services
        assessment = assessment_services.get_assessment(db, assessment_id)
        return assessment
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Risk calculation failed: {str(e)}")
