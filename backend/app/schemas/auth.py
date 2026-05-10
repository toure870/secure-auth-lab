"""Authentication request/response schemas with Pydantic validation."""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field, validator


class RegisterRequest(BaseModel):
    """User registration request schema."""
    
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=12)
    
    @validator("username")
    def username_alphanumeric(cls, v):
        if not v.replace("_", "").replace("-", "").isalnum():
            raise ValueError("Username must be alphanumeric (with - and _ allowed)")
        return v


class LoginRequest(BaseModel):
    """User login request schema."""
    
    email: EmailStr
    password: str


class RefreshTokenRequest(BaseModel):
    """Token refresh request schema."""
    
    refresh_token: str


class TokenResponse(BaseModel):
    """JWT token response schema."""
    
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


class UserResponse(BaseModel):
    """User profile response schema."""
    
    id: int
    username: str
    email: str
    is_active: bool
    is_verified: bool
    created_at: datetime
    last_login: Optional[datetime]
    
    class Config:
        from_attributes = True
