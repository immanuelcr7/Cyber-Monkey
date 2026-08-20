import uuid
from sqlalchemy import Column, String, Text, Boolean, ForeignKey, DateTime, UUID
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database.session import Base

class Target(Base):
    __tablename__ = "targets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    assessment_id = Column(UUID(as_uuid=True), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    target_type = Column(String, nullable=False)  # Domain, IP Address, URL
    target_value = Column(String, nullable=False)
    scope_status = Column(String, default="in_scope", nullable=False)  # in_scope, out_of_scope
    authorization_confirmed = Column(Boolean, default=False, nullable=False)
    description = Column(Text, nullable=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    assessment = relationship("Assessment", back_populates="targets")
