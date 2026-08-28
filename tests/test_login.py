"""Unit tests for user login Lambda handler."""

import json
import pytest
import mongomock
from backend.database.mongodb import set_database
from backend.security.password import hash_password
from backend.functions.login import handler


@pytest.fixture(autouse=True)
def setup_mock_db():
    """Inject mongomock database before each test."""
    client = mongomock.MongoClient()
    db = client["test_mfa_gateway"]
    set_database(db)
    yield db


def test_login_success(setup_mock_db):
    """Test successful credential verification triggering OTP generation and pending session creation."""
    db = setup_mock_db
    pwd_hash = hash_password("ValidPassword123!")
    user_res = db["users"].insert_one({
        "username": "testuser",
        "name": "Test User",
        "email": "test@example.com",
        "password_hash": pwd_hash,
        "mfa_enabled": True
    })

    payload = {
        "username": "testuser",
        "password": "ValidPassword123!"
    }
    event = {
        "body": json.dumps(payload),
        "requestContext": {"identity": {"sourceIp": "10.0.0.1"}}
    }

    res = handler(event, None)
    assert res["statusCode"] == 200

    body = json.loads(res["body"])
    assert body["success"] is True
    assert body["mfa_required"] is True
    assert "session_id" in body
    assert body["user_id"] == str(user_res.inserted_id)

    # Verify session inserted into DB
    session = db["sessions"].find_one({"_id": mongomock.ObjectId(body["session_id"])})
    assert session is not None
    assert session["status"] == "PENDING_MFA"


def test_login_invalid_password(setup_mock_db):
    """Test login failure with wrong password."""
    db = setup_mock_db
    pwd_hash = hash_password("ValidPassword123!")
    db["users"].insert_one({
        "username": "testuser",
        "email": "test@example.com",
        "password_hash": pwd_hash
    })

    payload = {
        "username": "testuser",
        "password": "WrongPassword123!"
    }
    event = {"body": json.dumps(payload)}

    res = handler(event, None)
    assert res["statusCode"] == 401
    body = json.loads(res["body"])
    assert body["error"] == "Invalid username or password."


def test_login_user_not_found():
    """Test login failure when username does not exist."""
    payload = {
        "username": "nonexistent",
        "password": "Password123!"
    }
    event = {"body": json.dumps(payload)}

    res = handler(event, None)
    assert res["statusCode"] == 401
    body = json.loads(res["body"])
    assert body["error"] == "Invalid username or password."
