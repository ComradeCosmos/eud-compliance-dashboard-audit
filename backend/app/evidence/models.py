from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from backend.app.database import Base

class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id", ondelete="CASCADE"), nullable=True)
    source = Column(String(50), nullable=False)  # e.g., 'AD', 'Nessus', 'EDR', 'Zscaler', 'ZAP', 'Manual'
    raw_data = Column(Text, nullable=False)
    hash_signature = Column(String(64), nullable=False)
    collected_at = Column(String(30), nullable=False)  # Isoformat timestamp string
    is_verified = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    assessment = relationship("Assessment", back_populates="evidence_list")
    findings = relationship("Finding", back_populates="evidence")
