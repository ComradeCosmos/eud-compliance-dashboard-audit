from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from backend.app.database import get_db
from backend.app.assessment.schemas import EvidenceCreate, EvidenceResponse
from backend.app.evidence import services as evidence_services

router = APIRouter(prefix="/api/evidence", tags=["Evidence Store"])

@router.post("/", response_model=EvidenceResponse)
def upload_evidence(evidence_in: EvidenceCreate, db: Session = Depends(get_db)):
    """Registers raw evidence, signs it with a SHA-256 hash, and stores it."""
    try:
        evidence = evidence_services.create_evidence(
            db=db,
            source=evidence_in.source,
            raw_data=evidence_in.raw_data,
            collected_at=evidence_in.collected_at,
            assessment_id=evidence_in.assessment_id
        )
        return evidence
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Evidence registration failed: {str(e)}")

@router.get("/", response_model=List[EvidenceResponse])
def get_evidence_list(
    assessment_id: Optional[int] = Query(None, description="Filter by Assessment ID"),
    db: Session = Depends(get_db)
):
    """Retrieves all signed evidence records, optionally filtered by assessment."""
    return evidence_services.list_evidence(db, assessment_id=assessment_id)

@router.get("/{evidence_id}", response_model=EvidenceResponse)
def get_evidence(evidence_id: int, db: Session = Depends(get_db)):
    """Retrieves a specific evidence record by its primary key ID."""
    evidence = evidence_services.get_evidence_by_id(db, evidence_id)
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return evidence

@router.get("/{evidence_id}/verify")
def verify_evidence_integrity(evidence_id: int, db: Session = Depends(get_db)):
    """
    Recalculates the SHA-256 signature for this evidence row and checks if it has been tampered with.
    """
    evidence = evidence_services.get_evidence_by_id(db, evidence_id)
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")
    
    is_valid = evidence_services.verify_evidence(db, evidence_id)
    
    # Reload evidence to get updated status
    db.refresh(evidence)
    
    return {
        "evidence_id": evidence_id,
        "is_verified": is_valid,
        "expected_hash": evidence.hash_signature,
        "status": "SECURE" if is_valid else "TAMPERED_OR_INVALID"
    }
