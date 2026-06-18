from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime
from backend.app.assessment.models import Assessment, Finding
from backend.app.assessment.schemas import AssessmentCreate, AssessmentUpdate, FindingCreate

def create_assessment(db: Session, assessment_in: AssessmentCreate) -> Assessment:
    """Creates a new security assessment audit session."""
    db_assessment = Assessment(
        name=assessment_in.name,
        environment=assessment_in.environment,
        status="IN_PROGRESS",
        overall_score=None
    )
    db.add(db_assessment)
    db.commit()
    db.refresh(db_assessment)
    return db_assessment

def get_assessment(db: Session, assessment_id: int) -> Optional[Assessment]:
    """Retrieves an assessment by its ID."""
    return db.query(Assessment).filter(Assessment.id == assessment_id).first()

def list_assessments(db: Session) -> List[Assessment]:
    """Lists all assessments in the database."""
    return db.query(Assessment).order_by(Assessment.created_at.desc()).all()

def update_assessment(db: Session, assessment_id: int, update_in: AssessmentUpdate) -> Optional[Assessment]:
    """Updates the score or status of an assessment."""
    db_assessment = get_assessment(db, assessment_id)
    if not db_assessment:
        return None
        
    update_data = update_in.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(db_assessment, key, value)
        
    db_assessment.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(db_assessment)
    return db_assessment

def delete_assessment(db: Session, assessment_id: int) -> bool:
    """Deletes an assessment and all associated findings and evidence."""
    db_assessment = get_assessment(db, assessment_id)
    if not db_assessment:
        return False
    db.delete(db_assessment)
    db.commit()
    return True

def create_finding(db: Session, finding_in: FindingCreate) -> Finding:
    """Creates an individual audit control finding for an assessment."""
    db_finding = Finding(
        assessment_id=finding_in.assessment_id,
        control_code=finding_in.control_code,
        control_title=finding_in.control_title,
        severity=finding_in.severity,
        status=finding_in.status,
        evidence_id=finding_in.evidence_id,
        details=finding_in.details,
        recommendation=finding_in.recommendation,
        type=finding_in.type
    )
    db.add(db_finding)
    db.commit()
    db.refresh(db_finding)
    return db_finding

def get_finding(db: Session, finding_id: int) -> Optional[Finding]:
    """Retrieves a single finding by ID."""
    return db.query(Finding).filter(Finding.id == finding_id).first()

def list_findings(db: Session, assessment_id: int) -> List[Finding]:
    """Lists all findings mapped to a specific assessment."""
    return db.query(Finding).filter(Finding.assessment_id == assessment_id).all()

def update_finding(
    db: Session, 
    finding_id: int, 
    status: str, 
    details: Optional[str] = None,
    recommendation: Optional[str] = None
) -> Optional[Finding]:
    """Allows manual override or updating of a finding's status and details."""
    db_finding = get_finding(db, finding_id)
    if not db_finding:
        return None
    db_finding.status = status
    if details is not None:
        db_finding.details = details
    if recommendation is not None:
        db_finding.recommendation = recommendation
    db_finding.checked_at = datetime.utcnow()
    db.commit()
    db.refresh(db_finding)
    return db_finding
