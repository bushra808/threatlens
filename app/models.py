from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.database import Base


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    external_alert_id = Column(String(255), nullable=True, index=True)
    source = Column(String(50), nullable=False, index=True)
    repository = Column(String(255), nullable=False, index=True)
    vulnerability_id = Column(String(255), nullable=False, index=True)
    package_name = Column(String(255), nullable=False, index=True)
    severity = Column(String(50), nullable=False, index=True)
    cvss_score = Column(Float, nullable=True)
    category = Column(String(255), nullable=True)
    status = Column(String(50), nullable=False, default="open")
    priority = Column(String(10), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    detected_at = Column(DateTime(timezone=True), nullable=False)
    last_seen_at = Column(DateTime(timezone=True), nullable=False)

    automation_events = relationship("AutomationEvent", back_populates="vulnerability")


class AutomationEvent(Base):
    __tablename__ = "automation_events"

    id = Column(Integer, primary_key=True, index=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=False)
    action_type = Column(String(50), nullable=False, index=True)
    destination = Column(String(255), nullable=False)
    status = Column(String(50), nullable=False)
    message = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    vulnerability = relationship("Vulnerability", back_populates="automation_events")
