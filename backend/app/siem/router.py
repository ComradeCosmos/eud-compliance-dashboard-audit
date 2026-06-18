from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel, ConfigDict
from typing import Optional
from backend.app.database import get_db
from backend.app.assessment.schemas import EvidenceResponse
from backend.app.siem import services as siem_services

router = APIRouter(prefix="/api/siem", tags=["SIEM Ingest Connector"])

class SiemIngestRequest(BaseModel):
    source: str  # AD, Nessus, EDR, Zscaler
    raw_log: str
    collected_at: str  # ISO format datetime string
    assessment_id: Optional[int] = None

@router.post("/ingest", response_model=EvidenceResponse)
def ingest_log(request: SiemIngestRequest, db: Session = Depends(get_db)):
    """
    Directly ingests security logs (e.g. AD, Nessus, EDR, Zscaler) into the platform's evidence store, 
    signing them cryptographically to ensure immutability.
    """
    try:
        evidence = siem_services.process_siem_log(
            db=db,
            source=request.source,
            raw_log=request.raw_log,
            collected_at=request.collected_at,
            assessment_id=request.assessment_id
        )
        return evidence
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Log ingestion failed: {str(e)}")
