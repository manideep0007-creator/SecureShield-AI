import os
import pytest
from fastapi.testclient import TestClient

from app.database.auth_db import (
    init_auth_db,
    get_user_by_email,
    create_user,
    authenticate_or_auto_register,
    authenticate_or_create_google_user,
    create_session,
    get_user_from_token,
    invalidate_session,
    init_user_isolated_db,
    AUTH_DB_PATH,
    USER_DBS_DIR
)
from main import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_auth():
    init_auth_db()
    try:
        import sqlite3
        with sqlite3.connect(AUTH_DB_PATH) as conn:
            conn.execute("DELETE FROM sessions")
            conn.execute("DELETE FROM users")
            conn.commit()
    except Exception:
        pass
    yield
    try:
        import sqlite3
        with sqlite3.connect(AUTH_DB_PATH) as conn:
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
    ok, auth_user, status = authenticate_or_auto_register(email, "SuperSecretPassword123!")
    assert ok is True
    assert status == "authenticated"
    assert auth_user["user_id"] == user["user_id"]

    # Invalid password
    bad_ok, bad_user, bad_status = authenticate_or_auto_register(email, "WrongPassword!")
    assert bad_ok is False
    assert bad_user is None
    assert bad_status == "invalid_password"


def test_login_auto_creates_account_when_not_registered():
    """Verify: 'when user click sign in button without having an acount in my app automatically account has to be created'"""
    new_email = "newbie_auto_onboard@secureshield.ai"
    assert get_user_by_email(new_email) is None

    response = client.post(
        "/api/auth/login",
        json={
            "email": new_email,
            "password": "AutoSecurePassword2026!",
            "full_name": "Newbie Automatic"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "auto_created"
    assert "token" in data
    assert data["user"]["email"] == new_email
    assert os.path.exists(data["user"]["db_file"])


def test_signup_already_existing_user_returns_conflict():
    """Verify: 'when a user clicks sign up and entered details which he is already registere then app should say user already existed'"""
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


def test_each_user_has_separate_database():
    """Verify: 'and also for each user a separate database has to be there'"""
    user_a = create_user(email="alice@shield.ai", password="pass_alice_123", full_name="Alice")
    user_b = create_user(email="bob@shield.ai", password="pass_bob_123", full_name="Bob")

    assert user_a["db_file"] != user_b["db_file"]
    assert os.path.exists(user_a["db_file"])
    assert os.path.exists(user_b["db_file"])
    assert user_a["user_id"] in user_a["db_file"]
    assert user_b["user_id"] in user_b["db_file"]
