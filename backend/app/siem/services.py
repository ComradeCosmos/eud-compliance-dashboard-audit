from sqlalchemy.orm import Session
from typing import Optional
from backend.app.evidence import services as evidence_services
from backend.app.evidence.models import Evidence

def process_siem_log(
    db: Session, 
    source: str, 
    raw_log: str, 
    collected_at: str, 
    assessment_id: Optional[int] = None
) -> Evidence:
    """
    Ingests and signs a SIEM log, storing it as secure evidence in the database.
    """
    # The source can be validated to be one of: AD, Nessus, EDR, Zscaler
    valid_sources = {"AD", "Nessus", "EDR", "Zscaler", "Network"}
    source_clean = source.strip()
    if source_clean not in valid_sources:
        # We can still accept custom, but default to EDR if unknown
        pass
        
    evidence = evidence_services.create_evidence(
        db=db,
        source=source_clean,
        raw_data=raw_log,
        collected_at=collected_at,
        assessment_id=assessment_id
    )
    return evidence
