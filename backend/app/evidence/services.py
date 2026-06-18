from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime
from backend.app.evidence.models import Evidence
from backend.app.security import calculate_evidence_hash, verify_evidence_integrity

def create_evidence(
    db: Session, 
    source: str, 
    raw_data: str, 
    collected_at: str, 
    assessment_id: Optional[int] = None
) -> Evidence:
    """
    Computes a cryptographic signature, registers the evidence, and stores it in the database.
    """
    # Use empty string if assessment_id is None for hash calculation consistency
    assoc_id = str(assessment_id) if assessment_id is not None else ""
    hash_sig = calculate_evidence_hash(raw_data, assoc_id, collected_at)
    
    db_evidence = Evidence(
        assessment_id=assessment_id,
        source=source,
        raw_data=raw_data,
        hash_signature=hash_sig,
        collected_at=collected_at,
        is_verified=True
    )
    db.add(db_evidence)
    db.commit()
    db.refresh(db_evidence)
    return db_evidence

def get_evidence_by_id(db: Session, evidence_id: int) -> Optional[Evidence]:
    """Retrieves an evidence record by ID."""
    return db.query(Evidence).filter(Evidence.id == evidence_id).first()

def list_evidence(db: Session, assessment_id: Optional[int] = None) -> List[Evidence]:
    """Lists all evidence, optionally filtered by assessment ID."""
    query = db.query(Evidence)
    if assessment_id is not None:
        query = query.filter(Evidence.assessment_id == assessment_id)
    return query.all()

def verify_evidence(db: Session, evidence_id: int) -> bool:
    """
    Loads evidence, recalculates SHA-256 signature, and updates is_verified status.
    Returns True if integrity is intact, False if tampering is detected.
    """
    evidence = get_evidence_by_id(db, evidence_id)
    if not evidence:
        return False
        
    assoc_id = str(evidence.assessment_id) if evidence.assessment_id is not None else ""
    is_valid = verify_evidence_integrity(
        raw_data=evidence.raw_data,
        assessment_id=assoc_id,
        collected_at=evidence.collected_at,
        expected_hash=evidence.hash_signature
    )
    
    # If the database status is different, update it
    if evidence.is_verified != is_valid:
        evidence.is_verified = is_valid
        db.commit()
        db.refresh(evidence)
        
    return is_valid

def verify_all_evidence_for_assessment(db: Session, assessment_id: int) -> bool:
    """Verifies the integrity of all evidence associated with an assessment."""
    evidence_list = list_evidence(db, assessment_id)
    all_ok = True
    for ev in evidence_list:
        if not verify_evidence(db, ev.id):
            all_ok = False
    return all_ok
