import logging
import os
import sys
import time
from typing import Optional, Tuple
from fastapi import APIRouter, HTTPException, Header, Depends
import httpx

from app.config.config import settings
from app.database.auth_db import (
    get_user_by_email,
    create_user,
    authenticate_user,
    authenticate_or_create_google_user,
    create_session,
    get_user_from_token,
    invalidate_session
)
from app.models.auth import RegisterRequest, LoginRequest, GoogleAuthRequest, AuthResponse, UserResponse

logger = logging.getLogger(__name__)
auth_router = APIRouter(prefix="/api/auth", tags=["Authentication & User Management"])


async def verify_google_id_token(
    id_token: Optional[str],
    client_supplied_email: str
) -> Tuple[bool, Optional[str], Optional[str], Optional[str]]:
    """
    Cryptographically verifies Google ID Token with Google OAuth2 servers.
    Validates signature, issuer, audience, expiration, and extracts the verified email and name.
    Never trusts client-supplied email without cryptographic token validation.
    Returns: (is_valid, error_message, verified_email, verified_name)
    """
    if not id_token or not id_token.strip():
        return False, "Google ID token is required.", None, None

    # Server configuration check: GOOGLE_CLIENT_ID must be configured
    configured_aud = settings.GOOGLE_CLIENT_ID
    if not configured_aud or not configured_aud.strip():
        logger.error("Google ID token verification failed: GOOGLE_CLIENT_ID is not configured on the server.")
        return False, "Server misconfiguration: Google OAuth client ID is not configured.", None, None

    clean_token = id_token.strip()

    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            resp = await client.get(
                "https://oauth2.googleapis.com/tokeninfo",
                params={"id_token": clean_token}
            )
            if resp.status_code != 200:
                return False, "Google ID token signature or token validation rejected by Google servers.", None, None

            token_data = resp.json()

            # 1. Validate issuer
            issuer = token_data.get("iss", "")
            if issuer not in ("accounts.google.com", "https://accounts.google.com"):
                return False, f"Untrusted token issuer: {issuer}", None, None

            # 2. Validate audience against configured client ID. Never skip audience validation.
            aud = token_data.get("aud")
            if not aud or aud.strip() != configured_aud.strip():
                return False, "Google ID token audience does not match configured Google Client ID.", None, None

            # 3. Validate expiration
            exp = token_data.get("exp")
            if not exp or int(exp) < int(time.time()):
                return False, "Google ID token has expired.", None, None

            # 4. Validate email verification
            email_verified = token_data.get("email_verified")
            if str(email_verified).lower() not in ("true", "1"):
                return False, "Google account email is not verified.", None, None

            # 5. Extract verified identity directly from token claims
            verified_email = token_data.get("email", "").strip().lower()
            if not verified_email:
                return False, "Google token does not contain a valid email claim.", None, None

            # 6. Prevent client from claiming an email that doesn't match the token
            if client_supplied_email and client_supplied_email.strip().lower() != verified_email:
                return False, "Supplied email does not match verified Google token identity.", None, None

            verified_name = token_data.get("name") or token_data.get("given_name")
            return True, None, verified_email, verified_name

    except Exception as exc:
        logger.error("Google token verification service error: %s", exc)
        return False, "Could not contact Google identity verification service.", None, None


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
    Explicit user registration (Phase 1):
    - Rejects duplicate email addresses with HTTP 409 Conflict.
    - Prevents race conditions atomically via SQLite UNIQUE constraints.
    - Provisions isolated threat database per user.
    """
    clean_email = payload.email.strip().lower()
    if not clean_email or "@" not in clean_email:
        raise HTTPException(status_code=422, detail="Invalid email format.")

    try:
        user = create_user(
            email=clean_email,
            password=payload.password,
            full_name=payload.full_name or "",
            provider="local"
        )
    except ValueError as exc:
        if "user_already_exists" in str(exc):
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "user_already_exists",
                    "message": "User already exists. Please sign in or use Google."
                }
            )
        raise HTTPException(status_code=400, detail="Registration failed.")

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
    Strict user authentication (Phase 1):
    - Separate from registration: NEVER auto-creates accounts on login.
    - Rejects unknown users with generic invalid credentials error.
    - Rejects password authentication for Google-created accounts without a password.
    """
    clean_email = payload.email.strip().lower()
    success, user, status_msg = authenticate_user(
        email=clean_email,
        password=payload.password
    )

    if not success or not user:
        if status_msg == "no_password_set":
            raise HTTPException(
                status_code=400,
                detail={
                    "code": "password_not_configured",
                    "message": "This account was created via Google Sign-In. Please sign in with Google."
                }
            )
        raise HTTPException(
            status_code=401,
            detail={
                "code": "invalid_credentials",
                "message": "Invalid email or password."
            }
        )

    token = create_session(user["user_id"])
    return AuthResponse(
        status="authenticated",
        message="Sign in successful. Threat vault loaded.",
        token=token,
        user=UserResponse(**user)
    )


@auth_router.post("/google", response_model=AuthResponse)
async def google_auth(payload: GoogleAuthRequest):
    """
    Sign in with Google (Phase 1):
    - Validates token signature, issuer, expiration, and audience.
    - Obtains verified email directly from validated Google claims.
    - Never trusts an unverified client-supplied email.
    - Implements secure account linking for existing accounts.
    """
    is_valid, error_msg, verified_email, verified_name = await verify_google_id_token(
        payload.id_token,
        payload.email
    )

    if not is_valid or not verified_email:
        raise HTTPException(
            status_code=401,
            detail={
                "code": "invalid_google_token",
                "message": error_msg or "Google authentication token verification failed."
            }
        )

    # Use verified email and display name from token
    user, status_msg = authenticate_or_create_google_user(
        email=verified_email,
        full_name=verified_name or payload.full_name or "",
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
    """Invalidate session token immediately."""
    if token:
        invalidate_session(token)
    return {"status": "success", "message": "Signed out successfully."}


@auth_router.get("/user/scans")
def get_current_user_scans(token: Optional[str] = Depends(extract_token), limit: int = 50):
    """
    Fetch scan history belonging strictly to currently authenticated user.
    Never trusts client-supplied user_id: uses session token ownership exclusively.
    """
    if not token:
        raise HTTPException(status_code=401, detail="Authentication token required.")
    user = get_user_from_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired session token.")
    from app.database.auth_db import get_user_scans
    return {"user_id": user["user_id"], "scans": get_user_scans(user["user_id"], limit=limit)}


@auth_router.get("/user/settings")
def get_current_user_settings(token: Optional[str] = Depends(extract_token)):
    """Fetch user settings belonging strictly to currently authenticated user."""
    if not token:
        raise HTTPException(status_code=401, detail="Authentication token required.")
    user = get_user_from_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired session token.")
    from app.database.auth_db import get_user_settings
    return {"user_id": user["user_id"], "settings": get_user_settings(user["user_id"])}


@auth_router.post("/user/settings")
def update_current_user_setting(payload: dict, token: Optional[str] = Depends(extract_token)):
    """Update user settings belonging strictly to currently authenticated user."""
    if not token:
        raise HTTPException(status_code=401, detail="Authentication token required.")
    user = get_user_from_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired session token.")
    key = payload.get("key")
    value = payload.get("value")
    if not key or value is None:
        raise HTTPException(status_code=422, detail="Fields 'key' and 'value' are required.")
    from app.database.auth_db import set_user_setting
    set_user_setting(user["user_id"], str(key), str(value))
    return {"status": "success", "user_id": user["user_id"], "key": key, "value": value}


@auth_router.get("/user/telemetry")
def get_current_user_telemetry(token: Optional[str] = Depends(extract_token), limit: int = 50):
    """Fetch telemetry events belonging strictly to currently authenticated user."""
    if not token:
        raise HTTPException(status_code=401, detail="Authentication token required.")
    user = get_user_from_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired session token.")
    from app.database.auth_db import get_user_telemetry
    return {"user_id": user["user_id"], "telemetry": get_user_telemetry(user["user_id"], limit=limit)}
