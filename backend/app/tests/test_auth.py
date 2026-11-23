import os
import sqlite3
import pytest
from fastapi.testclient import TestClient

from app.database.auth_db import (
    init_auth_db,
    get_user_by_email,
    create_user,
    authenticate_user,
    authenticate_or_create_google_user,
    create_session,
    get_user_from_token,
    invalidate_session,
    init_user_isolated_db,
    get_auth_db_path,
    get_user_dbs_dir
)
from main import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_auth():
    init_auth_db()
    try:
        with sqlite3.connect(get_auth_db_path()) as conn:
            conn.execute("DELETE FROM sessions")
            conn.execute("DELETE FROM users")
            conn.commit()
    except Exception:
        pass
    yield
    try:
        with sqlite3.connect(get_auth_db_path()) as conn:
            conn.execute("DELETE FROM sessions")
            conn.execute("DELETE FROM users")
            conn.commit()
    except Exception:
        pass


def test_auth_db_crud_and_password_hashing():
    email = "agent_test@secureshield.ai"
    user = create_user(email=email, password="SuperSecretPassword123!", full_name="Agent Tester")
    assert user["user_id"].startswith("usr_")
    assert user["email"] == email
    assert os.path.exists(user["db_file"])

    fetched = get_user_by_email(email)
    assert fetched is not None
    assert fetched["user_id"] == user["user_id"]

    # Valid login
    ok, auth_user, status = authenticate_user(email, "SuperSecretPassword123!")
    assert ok is True
    assert status == "authenticated"
    assert auth_user["user_id"] == user["user_id"]

    # Invalid password
    bad_ok, bad_user, bad_status = authenticate_user(email, "WrongPassword!")
    assert bad_ok is False
    assert bad_user is None
    assert bad_status == "invalid_password"


def test_login_rejects_unregistered_account_without_auto_creating():
    """Verify: 'Login must never automatically create an account. Unknown accounts must receive an appropriate authentication error.'"""
    new_email = "unregistered_user@secureshield.ai"
    assert get_user_by_email(new_email) is None

    response = client.post(
        "/api/auth/login",
        json={
            "email": new_email,
            "password": "AutoSecurePassword2026!",
            "full_name": "Unregistered Person"
        }
    )
    # Must reject with 401 Unauthorized, never auto-create!
    assert response.status_code == 401
    detail = response.json()["detail"]
    assert detail["code"] == "invalid_credentials"
    assert get_user_by_email(new_email) is None


def test_google_created_account_cannot_bypass_password_login():
    """Verify: 'Google-created accounts without passwords must not bypass password verification. Reject password login for accounts without a configured password.'"""
    google_email = "pure_google_user@gmail.com"
    user, _ = authenticate_or_create_google_user(email=google_email, full_name="Pure Google")
    assert user["provider"] == "google"

    # Attempt password login on this account
    response = client.post(
        "/api/auth/login",
        json={
            "email": google_email,
            "password": "AnyRandomPassword123!"
        }
    )
    # Must reject password login
    assert response.status_code in (400, 401)
    detail = response.json()["detail"]
    assert detail["code"] in ("password_not_configured", "invalid_credentials")


def test_signup_already_existing_user_returns_conflict():
    """Verify: 'when a user clicks sign up and entered details which he is already registered then app should say user already exists'"""
    existing_email = "veteran@secureshield.ai"
    # First register
    res1 = client.post(
        "/api/auth/register",
        json={"email": existing_email, "password": "InitialPassword123!", "full_name": "Veteran"}
    )
    assert res1.status_code == 201

    # Second register attempt with same email must fail with 409
    res2 = client.post(
        "/api/auth/register",
        json={"email": existing_email, "password": "SecondPassword123!", "full_name": "Veteran Duplicate"}
    )
    assert res2.status_code == 409
    detail = res2.json()["detail"]
    assert detail["code"] == "user_already_exists"
    assert "User already exists" in detail["message"]


def test_google_sign_in_flow():
    google_email = "google_user@gmail.com"
    response = client.post(
        "/api/auth/google",
        json={
            "email": google_email,
            "full_name": "Google User",
            "id_token": "mock_google_id_token_12345"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["user"]["email"] == google_email
    assert data["user"]["provider"] == "google"
    assert os.path.exists(data["user"]["db_file"])


def test_google_sign_in_rejects_empty_token_in_production(monkeypatch):
    from app.config.config import settings
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")

    response = client.post(
        "/api/auth/google",
        json={
            "email": "prod_hacker@gmail.com",
            "full_name": "Hacker",
            "id_token": ""
        }
    )
    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "invalid_google_token"


def test_each_user_has_separate_database():
    """Verify: 'and also for each user a separate database has to be there'"""
    user_a = create_user(email="alice@shield.ai", password="pass_alice_123", full_name="Alice")
    user_b = create_user(email="bob@shield.ai", password="pass_bob_123", full_name="Bob")

    assert user_a["db_file"] != user_b["db_file"]
    assert os.path.exists(user_a["db_file"])
    assert os.path.exists(user_b["db_file"])
    assert user_a["user_id"] in user_a["db_file"]
    assert user_b["user_id"] in user_b["db_file"]
