from fastapi import APIRouter, HTTPException, Header, Depends
from typing import Optional

from app.database.auth_db import (
    get_user_by_email,
    create_user,
    authenticate_or_auto_register,
    authenticate_or_create_google_user,
    create_session,
    get_user_from_token,
    invalidate_session
)
from app.models.auth import RegisterRequest, LoginRequest, GoogleAuthRequest, AuthResponse, UserResponse

auth_router = APIRouter(prefix="/api/auth", tags=["Authentication & User Management"])


def extract_token(
    authorization: Optional[str] = Header(None),
    x_auth_token: Optional[str] = Header(None)
) -> Optional[str]:
    if x_auth_token:
        return x_auth_token.strip()
    if authorization:
        parts = authorization.strip().split(" ", 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1].strip()
        return authorization.strip()
    return None


@auth_router.post("/register", response_model=AuthResponse, status_code=201)
def register(payload: RegisterRequest):
    """
    Explicit user registration:
    - If user already exists: returns 409 conflict
    - If not: creates user with isolated user database
    """
    clean_email = payload.email.strip().lower()
    existing_user = get_user_by_email(clean_email)
    if existing_user:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "user_already_exists",
                "message": "User already exists. Please sign in or use Google."
            }
        )

    user = create_user(
        email=clean_email,
        password=payload.password,
        full_name=payload.full_name or "",
        provider="local"
    )
    token = create_session(user["user_id"])
    return AuthResponse(
        status="created",
        message="Account created successfully",
        token=token,
        user=UserResponse(**user)
    )


@auth_router.post("/login", response_model=AuthResponse)
def login(payload: LoginRequest):
    """
    Sign in with auto-provisioning:
    - If user exists: validates password
    - If user DOES NOT exist: automatically registers and signs them in!
    """
    clean_email = payload.email.strip().lower()
    success, user, status_msg = authenticate_or_auto_register(
        email=clean_email,
        password=payload.password,
        full_name=payload.full_name
    )

    if not success or not user:
        raise HTTPException(
            status_code=401,
            detail={
                "code": "invalid_credentials",
                "message": "Incorrect password. Please verify your credentials."
            }
        )

    token = create_session(user["user_id"])
    friendly_msg = (
        "New account automatically initialized with isolated threat vault."
        if status_msg == "auto_created"
        else "Sign in successful. Threat vault loaded."
    )

    return AuthResponse(
        status=status_msg,
        message=friendly_msg,
        token=token,
        user=UserResponse(**user)
    )


@auth_router.post("/google", response_model=AuthResponse)
def google_auth(payload: GoogleAuthRequest):
    """
    Sign in with Google:
    - Automatically provisions new account if not previously registered
    - Logs in existing Google user
    """
    clean_email = payload.email.strip().lower()
    user, status_msg = authenticate_or_create_google_user(
        email=clean_email,
        full_name=payload.full_name or "",
        google_id=payload.id_token
    )
    token = create_session(user["user_id"])
    friendly_msg = (
        "Google account verified. Private vault initialized."
        if status_msg == "auto_created"
        else "Google sign in verified."
    )
    return AuthResponse(
        status=status_msg,
        message=friendly_msg,
        token=token,
        user=UserResponse(**user)
    )


@auth_router.get("/me", response_model=UserResponse)
def get_current_user(token: Optional[str] = Depends(extract_token)):
    """Fetch profile of currently authenticated user."""
    if not token:
        raise HTTPException(status_code=401, detail="Authentication token required.")
    user = get_user_from_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired session token.")
    return UserResponse(**user)


@auth_router.post("/logout")
def logout(token: Optional[str] = Depends(extract_token)):
    """Invalidate session token."""
    if token:
        invalidate_session(token)
    return {"status": "success", "message": "Signed out successfully."}
