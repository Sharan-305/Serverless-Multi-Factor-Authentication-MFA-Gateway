"""Unit tests for Logout Lambda handler."""

import json
import pytest
import mongomock
from backend.database.mongodb import set_database
from backend.security.jwt_handler import generate_jwt_token
from backend.functions.logout import handler


@pytest.fixture(autouse=True)
def setup_mock_db():
    """Inject mongomock database before each test."""
    client = mongomock.MongoClient()
    db = client["test_mfa_gateway"]
    set_database(db)
    yield db


def test_logout_success(setup_mock_db):
    """Test successful logout revokes session status in database."""
    db = setup_mock_db
    user_id = str(mongomock.ObjectId())
    session_res = db["sessions"].insert_one({
        "user_id": mongomock.ObjectId(user_id),
        "status": "ACTIVE"
    })
    session_id = str(session_res.inserted_id)

    token = generate_jwt_token(
        user_id=user_id,
        username="logoutuser",
        email="logout@example.com",
        session_id=session_id
    )

    event = {
        "headers": {"Authorization": f"Bearer {token}"},
        "requestContext": {
            "authorizer": {
                "principalId": user_id,
                "session_id": session_id
            }
        }
    }

    res = handler(event, None)
    assert res["statusCode"] == 200

    body = json.loads(res["body"])
    assert body["success"] is True

    # Verify session revoked in DB
    revoked_session = db["sessions"].find_one({"_id": session_res.inserted_id})
    assert revoked_session["status"] == "REVOKED"


def test_logout_missing_session():
    """Test logout fails when no session context or header is provided."""
    event = {"headers": {}}
    res = handler(event, None)
    assert res["statusCode"] == 400
    body = json.loads(res["body"])
    assert body["success"] is False
