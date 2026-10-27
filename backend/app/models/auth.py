from typing import Optional
from pydantic import BaseModel, Field


class RegisterRequest(BaseModel):
    email: str = Field(..., description="User email address")
    password: str = Field(..., min_length=6, description="User password (min 6 characters)")
    full_name: Optional[str] = Field(None, description="User full display name")


class LoginRequest(BaseModel):
    email: str = Field(..., description="User email address")
    password: str = Field(..., description="User password")
    full_name: Optional[str] = Field(None, description="Optional name if auto-creating account")


class GoogleAuthRequest(BaseModel):
    email: str = Field(..., description="Verified Google account email")
    full_name: Optional[str] = Field(None, description="Google profile name")
    id_token: Optional[str] = Field(None, description="Google OAuth ID token or client token")


class UserResponse(BaseModel):
    user_id: str
    email: str
    full_name: str
    provider: str
    db_file: str
    created_at: str
    last_login_at: str


class AuthResponse(BaseModel):
    status: str
    message: str
    token: str
    user: UserResponse
