from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field


# PUBLIC_INTERFACE
class RegisterRequest(BaseModel):
    """Request payload for user registration."""
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., min_length=8, description="Password (min 8 characters)")
    display_name: Optional[str] = Field(None, description="Optional display name")


# PUBLIC_INTERFACE
class LoginRequest(BaseModel):
    """Request payload for user login."""
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., description="Password")


# PUBLIC_INTERFACE
class TokenResponse(BaseModel):
    """JWT tokens returned on successful authentication."""
    access_token: str = Field(..., description="Access token (JWT) for API calls")
    token_type: str = Field("bearer", description="Token type is always 'bearer'")


# PUBLIC_INTERFACE
class UserOut(BaseModel):
    """Public representation of a user."""
    id: str = Field(..., description="User ID")
    email: EmailStr = Field(..., description="Email")
    display_name: Optional[str] = Field(None, description="Display name")
    created_at: Optional[datetime] = Field(None, description="Creation timestamp")


# PUBLIC_INTERFACE
class MessageResponse(BaseModel):
    """Generic message response model."""
    message: str = Field(..., description="Human-readable message")
