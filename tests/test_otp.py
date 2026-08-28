"""Unit tests for OTP generation, resend, and verification handlers."""

import json
import pytest
import mongomock
from datetime import datetime, timedelta, timezone
from backend.database.mongodb import set_database
from backend.security.otp_handler import generate_otp, hash_otp, verify_otp_hash
from backend.functions.verify_otp import handler as verify_handler
from backend.functions.send_otp import handler as send_otp_handler


@pytest.fixture(autouse=True)
def setup_mock_db():
    """Inject mongomock database before each test."""
    client = mongomock.MongoClient()
    db = client["test_mfa_gateway"]
    set_database(db)
    yield db


def test_otp_helpers():
    """Test OTP numeric generation and SHA-256 hashing functions."""
    otp = generate_otp(6)
    assert len(otp) == 6
    assert otp.isdigit()

    hashed = hash_otp(otp)
    assert len(hashed) == 64  # SHA-256 hex string length
    assert verify_otp_hash(otp, hashed) is True
    assert verify_otp_hash("000000", hashed) is False


def test_verify_otp_success(setup_mock_db):
    """Test successful OTP verification issuing a valid JWT token."""
    db = setup_mock_db
    user_res = db["users"].insert_one({
        "username": "otpuser",
        "name": "OTP User",
        "email": "otp@example.com",
        "password_hash": "hash"
    })

    raw_otp = "123456"
    hashed_otp = hash_otp(raw_otp)
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()

    session_res = db["sessions"].insert_one({
        "user_id": user_res.inserted_id,
        "otp_hash": hashed_otp,
        "expires_at": expires_at,
        "attempts": 0,
        "status": "PENDING_MFA",
        "token": None
    })
    session_id = str(session_res.inserted_id)

    payload = {"session_id": session_id, "otp": raw_otp}
    event = {"body": json.dumps(payload)}

    res = verify_handler(event, None)
    assert res["statusCode"] == 200

    body = json.loads(res["body"])
    assert body["success"] is True
    assert "token" in body
    assert body["user"]["username"] == "otpuser"

    # Check session updated to ACTIVE in DB
    updated_session = db["sessions"].find_one({"_id": session_res.inserted_id})
    assert updated_session["status"] == "ACTIVE"
    assert updated_session["token"] == body["token"]


def test_verify_otp_invalid_code(setup_mock_db):
    """Test verification rejection with incorrect OTP code."""
    db = setup_mock_db
    user_res = db["users"].insert_one({"username": "user", "email": "u@ex.com"})

    raw_otp = "123456"
    session_res = db["sessions"].insert_one({
        "user_id": user_res.inserted_id,
        "otp_hash": hash_otp(raw_otp),
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        "attempts": 0,
        "status": "PENDING_MFA"
    })

    payload = {"session_id": str(session_res.inserted_id), "otp": "999999"}
    event = {"body": json.dumps(payload)}

    res = verify_handler(event, None)
    assert res["statusCode"] == 400
    body = json.loads(res["body"])
    assert "Invalid OTP code" in body["error"]


def test_verify_otp_max_attempts_lockout(setup_mock_db):
    """Test lockout when attempt limit is reached."""
    db = setup_mock_db
    user_res = db["users"].insert_one({"username": "user", "email": "u@ex.com"})

    session_res = db["sessions"].insert_one({
        "user_id": user_res.inserted_id,
        "otp_hash": hash_otp("123456"),
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        "attempts": 3,
        "status": "PENDING_MFA"
    })

    payload = {"session_id": str(session_res.inserted_id), "otp": "123456"}
    event = {"body": json.dumps(payload)}

    res = verify_handler(event, None)
    assert res["statusCode"] == 429
    body = json.loads(res["body"])
    assert "exceeded" in body["error"]


def test_send_otp_smtp_success(monkeypatch):
    """Test dispatching OTP via SMTP successfully."""
    from unittest.mock import MagicMock
    import smtplib
    from backend.security.otp_handler import send_otp
    from backend.utils.config import config

    mock_smtp = MagicMock()
    monkeypatch.setattr(smtplib, "SMTP", lambda host, port, timeout: mock_smtp)
    monkeypatch.setattr(config, "OTP_PROVIDER", "smtp")
    monkeypatch.setattr(config, "SMTP_USERNAME", "user@example.com")
    monkeypatch.setattr(config, "SMTP_PASSWORD", "secret")

    result = send_otp("user@example.com", "654321", "email")
    assert result["status"] == "SUCCESS"
    assert result["provider"] == "smtp"
    assert mock_smtp.send_message.called


def test_send_otp_smtp_failure_fallback(monkeypatch):
    """Test graceful fallback when SMTP server is unreachable."""
    import smtplib
    from backend.security.otp_handler import send_otp
    from backend.utils.config import config

    def failing_smtp(*args, **kwargs):
        raise smtplib.SMTPException("Connection refused")

    monkeypatch.setattr(smtplib, "SMTP", failing_smtp)
    monkeypatch.setattr(config, "OTP_PROVIDER", "smtp")

    result = send_otp("user@example.com", "654321", "email")
    assert result["status"] == "SUCCESS"
    assert result["provider"] == "smtp_fallback_mock"
    assert "Connection refused" in result["error"]


def test_send_otp_mock_provider(monkeypatch):
    """Test mock OTP dispatch provider."""
    from backend.security.otp_handler import send_otp
    from backend.utils.config import config

    monkeypatch.setattr(config, "OTP_PROVIDER", "mock")
    result = send_otp("test@example.com", "112233", "email")
    assert result["status"] == "SUCCESS"
    assert result["provider"] == "mock"

