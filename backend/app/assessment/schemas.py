from pydantic import BaseModel, ConfigDict
from typing import List, Optional
from datetime import datetime

# ----------------- Evidence Schemas -----------------
class EvidenceBase(BaseModel):
    source: str
    raw_data: str
    collected_at: str

class EvidenceCreate(EvidenceBase):
    assessment_id: Optional[int] = None

class EvidenceResponse(EvidenceBase):
    id: int
    assessment_id: Optional[int] = None
    hash_signature: str
    is_verified: bool
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

# ----------------- Finding Schemas -----------------
class FindingBase(BaseModel):
    control_code: str
    control_title: str
    severity: str
    status: str
    details: Optional[str] = None
    recommendation: Optional[str] = None
    type: str

class FindingCreate(FindingBase):
    assessment_id: int
    evidence_id: Optional[int] = None

class FindingResponse(FindingBase):
    id: int
    assessment_id: int
    evidence_id: Optional[int] = None
    checked_at: datetime
    model_config = ConfigDict(from_attributes=True)

# ----------------- Assessment Schemas -----------------
class AssessmentBase(BaseModel):
    name: str
    environment: str = "Development"  # Production, UAT, Development

class AssessmentCreate(AssessmentBase):
    pass

class AssessmentUpdate(BaseModel):
    status: Optional[str] = None
    overall_score: Optional[float] = None
    environment: Optional[str] = None

class AssessmentResponse(AssessmentBase):
    id: int
    status: str
    overall_score: Optional[float] = None
    created_at: datetime
    updated_at: datetime
    
    model_config = ConfigDict(from_attributes=True)

class AssessmentDetailResponse(AssessmentResponse):
    findings: List[FindingResponse] = []
    evidence_list: List[EvidenceResponse] = []
    
    model_config = ConfigDict(from_attributes=True)
