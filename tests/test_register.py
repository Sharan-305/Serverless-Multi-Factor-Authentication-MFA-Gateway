"""Unit tests for user registration Lambda handler."""

import json
import pytest
import mongomock
from backend.database.mongodb import set_database
from backend.functions.register import handler


@pytest.fixture(autouse=True)
def setup_mock_db():
    """Inject mongomock database before each test."""
    client = mongomock.MongoClient()
    db = client["test_mfa_gateway"]
    set_database(db)
    yield db


def test_register_success():
    """Test successful user registration with valid payload."""
    payload = {
        "username": "johndoe",
        "name": "John Doe",
        "email": "john@example.com",
        "password": "SecurePassword123!"
    }
    event = {
        "body": json.dumps(payload),
        "requestContext": {"identity": {"sourceIp": "192.168.1.1"}}
    }

    res = handler(event, None)
    assert res["statusCode"] == 201

    body = json.loads(res["body"])
    assert body["success"] is True
    assert body["username"] == "johndoe"
    assert body["email"] == "john@example.com"
    assert "user_id" in body


def test_register_duplicate_username(setup_mock_db):
    """Test rejection when registering duplicate username."""
    db = setup_mock_db
    db["users"].insert_one({
        "username": "johndoe",
        "email": "existing@example.com",
        "password_hash": "hash"
    })

    payload = {
        "username": "johndoe",
        "name": "John Doe",
        "email": "john_new@example.com",
        "password": "SecurePassword123!"
    }
    event = {"body": json.dumps(payload)}

    res = handler(event, None)
    assert res["statusCode"] == 409
    body = json.loads(res["body"])
    assert body["success"] is False


def test_register_weak_password():
    """Test rejection when password does not meet complexity requirements."""
    payload = {
        "username": "johndoe",
        "name": "John Doe",
        "email": "john@example.com",
        "password": "simple"
    }
    event = {"body": json.dumps(payload)}

    res = handler(event, None)
    assert res["statusCode"] == 400
    body = json.loads(res["body"])
    assert "Password must be at least" in body["error"]
