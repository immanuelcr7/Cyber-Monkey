import uuid
from sqlalchemy import Column, String, Text, Date, DateTime, UUID
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database.session import Base

class Assessment(Base):
    __tablename__ = "assessments"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, nullable=False)
    organization = Column(String, nullable=True)
    assessment_type = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    start_date = Column(Date, nullable=True)
    end_date = Column(Date, nullable=True)
    status = Column(String, default="active", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    targets = relationship("Target", back_populates="assessment", cascade="all, delete-orphan")
