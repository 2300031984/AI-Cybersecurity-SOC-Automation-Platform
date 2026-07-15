from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from pydantic import BaseModel

from backend.app.core.security import (
    verify_password, 
    create_access_token, 
    create_refresh_token, 
    decode_token
)
from backend.app.database.session import get_db
from backend.app.api.deps import get_current_user
from backend.app.models.user import User
from backend.app.models.audit_log import AuditLog
from backend.app.schemas.auth import Token
from backend.app.schemas.user import UserOut

router = APIRouter()

class RefreshRequest(BaseModel):
    refresh_token: str

@router.post("/login", response_model=Token)
def login(
    db: Session = Depends(get_db), 
    form_data: OAuth2PasswordRequestForm = Depends()
):
    """
    Authenticate user and retrieve access and refresh tokens.
    Supports standard form-data login compatible with Swagger UI.
    """
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Inactive user account"
        )
        
    # Generate tokens
    access_token = create_access_token(subject=user.id)
    refresh_token = create_refresh_token(subject=user.id)
    
    # Audit log
    audit_entry = AuditLog(
        user_id=user.id,
        organization_id=user.organization_id,
        action="LOGIN",
        resource="auth/login",
        details=f"User '{user.username}' logged in successfully."
    )
    db.add(audit_entry)
    db.commit()
    
    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        role=user.role,
        username=user.username,
        org_name=user.organization.name if user.organization else None
    )

@router.post("/refresh", response_model=Token)
def refresh_token(
    payload: RefreshRequest, 
    db: Session = Depends(get_db)
):
    """
    Issue a new Access Token using a valid Refresh Token.
    """
    token_payload = decode_token(payload.refresh_token)
    if token_payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
        
    user_id_str: str = token_payload.get("sub")
    token_type: str = token_payload.get("type")
    
    if user_id_str is None or token_type != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token payload"
        )
        
    user = db.query(User).filter(User.id == int(user_id_str)).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user account"
        )
        
    # Issue fresh tokens
    new_access = create_access_token(subject=user.id)
    new_refresh = create_refresh_token(subject=user.id)
    
    return Token(
        access_token=new_access,
        refresh_token=new_refresh,
        role=user.role,
        username=user.username
    )

@router.get("/me", response_model=UserOut)
def read_current_user(current_user: User = Depends(get_current_user)):
    """
    Retrieve profile details of the authenticated user.
    """
    return current_user

@router.post("/logout")
def logout(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Log out the current user and write an audit entry.
    """
    audit_entry = AuditLog(
        user_id=current_user.id,
        organization_id=current_user.organization_id,
        action="LOGOUT",
        resource="auth/logout",
        details=f"User '{current_user.username}' logged out successfully."
    )
    db.add(audit_entry)
    db.commit()
    return {"message": "Logged out successfully"}
