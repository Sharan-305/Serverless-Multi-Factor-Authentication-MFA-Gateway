"""Unit tests for AWS Lambda Authorizer (Policy Enforcement Point)."""

import pytest
import mongomock
from backend.database.mongodb import set_database
from backend.security.jwt_handler import generate_jwt_token
from backend.functions.authorizer import handler


@pytest.fixture(autouse=True)
def setup_mock_db():
    """Inject mongomock database before each test."""
    client = mongomock.MongoClient()
    db = client["test_mfa_gateway"]
    set_database(db)
    yield db


def test_authorizer_allow_valid_token(setup_mock_db):
    """Test custom authorizer generates Allow policy for valid active session."""
    db = setup_mock_db
    user_id = str(mongomock.ObjectId())
    session_res = db["sessions"].insert_one({
        "user_id": mongomock.ObjectId(user_id),
        "status": "ACTIVE"
    })
    session_id = str(session_res.inserted_id)

    token = generate_jwt_token(
        user_id=user_id,
        username="authuser",
        email="auth@example.com",
        session_id=session_id
    )

    event = {
        "authorizationToken": f"Bearer {token}",
        "methodArn": "arn:aws:execute-api:us-east-1:123456789012:api123/dev/GET/dashboard-data"
    }

    policy = handler(event, None)
    assert policy["principalId"] == user_id
    statements = policy["policyDocument"]["Statement"]
    assert statements[0]["Effect"] == "Allow"
    assert policy["context"]["username"] == "authuser"


def test_authorizer_deny_revoked_session(setup_mock_db):
    """Test authorizer denies access if session is marked as REVOKED in MongoDB."""
    db = setup_mock_db
    user_id = str(mongomock.ObjectId())
    session_res = db["sessions"].insert_one({
        "user_id": mongomock.ObjectId(user_id),
        "status": "REVOKED"
    })
    session_id = str(session_res.inserted_id)

    token = generate_jwt_token(
        user_id=user_id,
        username="authuser",
        email="auth@example.com",
        session_id=session_id
    )

    event = {
        "authorizationToken": f"Bearer {token}",
        "methodArn": "arn:aws:execute-api:us-east-1:123456789012:api123/dev/GET/dashboard-data"
    }

    policy = handler(event, None)
    statements = policy["policyDocument"]["Statement"]
    assert statements[0]["Effect"] == "Deny"


def test_authorizer_deny_invalid_jwt():
    """Test authorizer denies access if JWT is malformed or invalid."""
    event = {
        "authorizationToken": "Bearer invalid.jwt.token",
        "methodArn": "arn:aws:execute-api:us-east-1:123456789012:api123/dev/GET/dashboard-data"
    }

    policy = handler(event, None)
    statements = policy["policyDocument"]["Statement"]
    assert statements[0]["Effect"] == "Deny"


def test_authorizer_deny_missing_header():
    """Test authorizer denies access when Authorization header is omitted."""
    event = {
        "methodArn": "arn:aws:execute-api:us-east-1:123456789012:api123/dev/GET/dashboard-data"
    }

    policy = handler(event, None)
    statements = policy["policyDocument"]["Statement"]
    assert statements[0]["Effect"] == "Deny"
