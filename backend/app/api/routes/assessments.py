from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from uuid import UUID

from app.database.session import get_db
from app.models.assessment import Assessment
from app.models.target import Target
from app.schemas.assessment import (
    AssessmentCreate,
    AssessmentUpdate,
    AssessmentResponse,
    AssessmentDetailResponse,
)
from app.schemas.target import TargetCreate, TargetResponse
from app.utils.target_validation import (
    validate_domain,
    validate_ip,
    validate_url,
)
from app.services.authorization import is_target_authorized

router = APIRouter()

@router.post("/", response_model=AssessmentResponse, status_code=status.HTTP_201_CREATED)
def create_assessment(assessment_in: AssessmentCreate, db: Session = Depends(get_db)):
    valid_types = {"External Network", "Internal Network", "Web Application", "API", "Cloud", "Other"}
    if assessment_in.assessment_type not in valid_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid assessment type. Must be one of: {', '.join(valid_types)}"
        )
    
    valid_statuses = {"active", "completed", "archived"}
    if assessment_in.status not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}"
        )

    db_assessment = Assessment(**assessment_in.model_dump())
    db.add(db_assessment)
    db.commit()
    db.refresh(db_assessment)
    db_assessment.target_count = 0
    return db_assessment

@router.get("/", response_model=List[AssessmentResponse])
def read_assessments(db: Session = Depends(get_db)):
    assessments = db.query(Assessment).all()
    for a in assessments:
        a.target_count = len(a.targets)
    return assessments

@router.get("/{assessment_id}", response_model=AssessmentDetailResponse)
def read_assessment(assessment_id: UUID, db: Session = Depends(get_db)):
    db_assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not db_assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Assessment not found"
        )
    db_assessment.target_count = len(db_assessment.targets)
    return db_assessment

@router.patch("/{assessment_id}", response_model=AssessmentResponse)
def update_assessment(assessment_id: UUID, assessment_in: AssessmentUpdate, db: Session = Depends(get_db)):
    db_assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not db_assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Assessment not found"
        )
    
    update_data = assessment_in.model_dump(exclude_unset=True)
    
    if "assessment_type" in update_data:
        valid_types = {"External Network", "Internal Network", "Web Application", "API", "Cloud", "Other"}
        if update_data["assessment_type"] not in valid_types:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid assessment type. Must be one of: {', '.join(valid_types)}"
            )

    if "status" in update_data:
        valid_statuses = {"active", "completed", "archived"}
        if update_data["status"] not in valid_statuses:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}"
            )

    for field, value in update_data.items():
        setattr(db_assessment, field, value)
        
    db.commit()
    db.refresh(db_assessment)
    db_assessment.target_count = len(db_assessment.targets)
    return db_assessment

@router.delete("/{assessment_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_assessment(assessment_id: UUID, db: Session = Depends(get_db)):
    db_assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not db_assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Assessment not found"
        )
    db.delete(db_assessment)
    db.commit()
    return None

# Target sub-routes
@router.post("/{assessment_id}/targets", response_model=TargetResponse, status_code=status.HTTP_201_CREATED)
def create_target(assessment_id: UUID, target_in: TargetCreate, db: Session = Depends(get_db)):
    db_assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not db_assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Assessment not found"
        )

    valid_target_types = {"Domain", "IP Address", "URL"}
    if target_in.target_type not in valid_target_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid target type. Must be one of: {', '.join(valid_target_types)}"
        )

    valid_scope_statuses = {"in_scope", "out_of_scope"}
    if target_in.scope_status not in valid_scope_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid scope status. Must be one of: {', '.join(valid_scope_statuses)}"
        )

    if target_in.target_type == "Domain":
        if not validate_domain(target_in.target_value):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid target value. Please provide a valid domain name syntax (e.g. example.com)."
            )
    elif target_in.target_type == "IP Address":
        if not validate_ip(target_in.target_value):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid target value. Please provide a valid IPv4 or IPv6 address format (e.g. 192.168.1.1)."
            )
    elif target_in.target_type == "URL":
        if not validate_url(target_in.target_value):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid target value. Please provide a valid http/https URL format (e.g. https://example.com)."
            )

    db_target = Target(**target_in.model_dump(), assessment_id=assessment_id)
    if db_target.scope_status == "in_scope" and not is_target_authorized(db_target):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authorization confirmation is required for an in-scope target."
        )
    db.add(db_target)
    db.commit()
    db.refresh(db_target)
    return db_target

@router.get("/{assessment_id}/targets", response_model=List[TargetResponse])
def read_assessment_targets(assessment_id: UUID, db: Session = Depends(get_db)):
    db_assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not db_assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Assessment not found"
        )
    return db_assessment.targets
