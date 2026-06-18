from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Float
from sqlalchemy.orm import relationship
from datetime import datetime
from backend.app.database import Base

class Assessment(Base):
    __tablename__ = "assessments"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(100), nullable=False)
    environment = Column(String(30), default="Development")  # Production, UAT, Development
    status = Column(String(20), default="IN_PROGRESS")  # IN_PROGRESS, COMPLETED
    overall_score = Column(Float, nullable=True)  # Calculated score (0.0 to 100.0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    evidence_list = relationship("Evidence", back_populates="assessment", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="assessment", cascade="all, delete-orphan")

class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    control_code = Column(String(20), nullable=False)  # e.g., CTRL-001
    control_title = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)  # HIGH, MEDIUM, LOW
    status = Column(String(20), nullable=False)  # PASS, FAIL
    evidence_id = Column(Integer, ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True)
    details = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)
    type = Column(String(20), nullable=False)  # AUTOMATED, SCANNER, MANUAL
    checked_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    assessment = relationship("Assessment", back_populates="findings")
    evidence = relationship("Evidence", back_populates="findings")
