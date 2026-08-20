from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from uuid import UUID

from app.database.session import get_db
from app.models.target import Target
from app.schemas.target import TargetUpdate, TargetResponse
from app.utils.target_validation import (
    validate_domain,
    validate_ip,
    validate_url,
)
from app.services.authorization import is_target_authorized

router = APIRouter()

@router.get("/{target_id}", response_model=TargetResponse)
def read_target(target_id: UUID, db: Session = Depends(get_db)):
    db_target = db.query(Target).filter(Target.id == target_id).first()
    if not db_target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found"
        )
    return db_target

@router.patch("/{target_id}", response_model=TargetResponse)
def update_target(target_id: UUID, target_in: TargetUpdate, db: Session = Depends(get_db)):
    db_target = db.query(Target).filter(Target.id == target_id).first()
    if not db_target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found"
        )
    
    update_data = target_in.model_dump(exclude_unset=True)
    
    new_type = update_data.get("target_type", db_target.target_type)
    new_value = update_data.get("target_value", db_target.target_value)
    
    if "target_type" in update_data or "target_value" in update_data:
        valid_target_types = {"Domain", "IP Address", "URL"}
        if new_type not in valid_target_types:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid target type. Must be one of: {', '.join(valid_target_types)}"
            )
            
        if new_type == "Domain":
            if not validate_domain(new_value):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid target value. Please provide a valid domain name syntax (e.g. example.com)."
                )
        elif new_type == "IP Address":
            if not validate_ip(new_value):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid target value. Please provide a valid IPv4 or IPv6 address format (e.g. 192.168.1.1)."
                )
        elif new_type == "URL":
            if not validate_url(new_value):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid target value. Please provide a valid http/https URL format (e.g. https://example.com)."
                )

    if "scope_status" in update_data:
        valid_scope_statuses = {"in_scope", "out_of_scope"}
        if update_data["scope_status"] not in valid_scope_statuses:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid scope status. Must be one of: {', '.join(valid_scope_statuses)}"
            )

    for field, value in update_data.items():
        setattr(db_target, field, value)
        
    if db_target.scope_status == "in_scope" and not is_target_authorized(db_target):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authorization confirmation is required for an in-scope target."
        )
        
    db.commit()
    db.refresh(db_target)
    return db_target

@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_target(target_id: UUID, db: Session = Depends(get_db)):
    db_target = db.query(Target).filter(Target.id == target_id).first()
    if not db_target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found"
        )
    db.delete(db_target)
    db.commit()
    return None
