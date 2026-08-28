"""Session model for MongoDB 'sessions' collection operations."""

from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from bson import ObjectId
from backend.database.mongodb import get_database


class SessionModel:
    """Data Access Object for Session & OTP documents."""

    STATUS_PENDING = "PENDING_MFA"
    STATUS_ACTIVE = "ACTIVE"
    STATUS_EXPIRED = "EXPIRED"
    STATUS_REVOKED = "REVOKED"

    @staticmethod
    def get_collection():
        """Retrieve MongoDB sessions collection."""
        db = get_database()
        if db is None:
            raise RuntimeError("Database connection not initialized")
        return db["sessions"]

    @classmethod
    def create_otp_session(
        cls,
        user_id: str,
        otp_hash: str,
        expiry_minutes: int = 5
    ) -> Dict[str, Any]:
        """Create a new session document initialized with an OTP for MFA verification."""
        collection = cls.get_collection()
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=expiry_minutes)

        session_doc = {
            "user_id": ObjectId(user_id) if isinstance(user_id, str) else user_id,
            "otp_hash": otp_hash,
            "expires_at": expires_at.isoformat(),
            "attempts": 0,
            "status": cls.STATUS_PENDING,
            "token": None,
            "created_at": now.isoformat(),
        }
        result = collection.insert_one(session_doc)
        session_doc["_id"] = result.inserted_id
        return session_doc

    @classmethod
    def find_by_id(cls, session_id: str) -> Optional[Dict[str, Any]]:
        """Look up session by ObjectId."""
        collection = cls.get_collection()
        try:
            return collection.find_one({"_id": ObjectId(session_id)})
        except Exception:
            return None

    @classmethod
    def find_by_token(cls, token: str) -> Optional[Dict[str, Any]]:
        """Look up session by issued JWT token."""
        collection = cls.get_collection()
        return collection.find_one({"token": token})

    @classmethod
    def find_active_session_for_user(cls, user_id: str) -> Optional[Dict[str, Any]]:
        """Find the latest active or pending session for a user."""
        collection = cls.get_collection()
        uid = ObjectId(user_id) if isinstance(user_id, str) else user_id
        return collection.find_one(
            {"user_id": uid, "status": {"$in": [cls.STATUS_PENDING, cls.STATUS_ACTIVE]}},
            sort=[("created_at", -1)]
        )

    @classmethod
    def increment_attempts(cls, session_id: str) -> int:
        """Increment failed OTP attempt count and return new attempt count."""
        collection = cls.get_collection()
        result = collection.find_one_and_update(
            {"_id": ObjectId(session_id)},
            {"$inc": {"attempts": 1}},
            return_document=True
        )
        return result.get("attempts", 0) if result else 0

    @classmethod
    def activate_session(cls, session_id: str, jwt_token: str) -> bool:
        """Mark session as ACTIVE and store the issued JWT token."""
        collection = cls.get_collection()
        try:
            res = collection.update_one(
                {"_id": ObjectId(session_id)},
                {
                    "$set": {
                        "status": cls.STATUS_ACTIVE,
                        "token": jwt_token,
                        "activated_at": datetime.now(timezone.utc).isoformat()
                    }
                }
            )
            return res.modified_count > 0
        except Exception:
            return False

    @classmethod
    def mark_expired(cls, session_id: str) -> bool:
        """Mark session status as EXPIRED."""
        collection = cls.get_collection()
        try:
            res = collection.update_one(
                {"_id": ObjectId(session_id)},
                {"$set": {"status": cls.STATUS_EXPIRED}}
            )
            return res.modified_count > 0
        except Exception:
            return False

    @classmethod
    def revoke_session(cls, session_id: str) -> bool:
        """Mark session status as REVOKED (token invalidation on logout)."""
        collection = cls.get_collection()
        try:
            res = collection.update_one(
                {"_id": ObjectId(session_id)},
                {"$set": {"status": cls.STATUS_REVOKED, "revoked_at": datetime.now(timezone.utc).isoformat()}}
            )
            return res.modified_count > 0
        except Exception:
            return False
