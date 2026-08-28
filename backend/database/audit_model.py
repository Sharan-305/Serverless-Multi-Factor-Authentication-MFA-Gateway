"""Audit log model for MongoDB 'audit_logs' collection."""

from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from bson import ObjectId
from backend.database.mongodb import get_database


class AuditModel:
    """Data Access Object for Audit Log documents."""

    EVENT_REGISTER = "REGISTER_SUCCESS"
    EVENT_LOGIN_SUCCESS = "LOGIN_SUCCESS"
    EVENT_LOGIN_FAIL = "LOGIN_FAIL"
    EVENT_OTP_SENT = "OTP_SENT"
    EVENT_OTP_VERIFIED = "OTP_VERIFIED"
    EVENT_OTP_FAILED = "OTP_FAILED"
    EVENT_OTP_LOCKOUT = "OTP_LOCKOUT"
    EVENT_LOGOUT = "LOGOUT"
    EVENT_UNAUTHORIZED = "UNAUTHORIZED_ACCESS"

    @staticmethod
    def get_collection():
        """Retrieve MongoDB audit_logs collection."""
        db = get_database()
        if db is None:
            raise RuntimeError("Database connection not initialized")
        return db["audit_logs"]

    @classmethod
    def log_event(
        cls,
        event: str,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Record an authentication security event in audit_logs."""
        try:
            collection = cls.get_collection()
            doc = {
                "user_id": ObjectId(user_id) if user_id and ObjectId.is_valid(user_id) else user_id,
                "event": event,
                "ip_address": ip_address or "0.0.0.0",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            if details:
                doc["details"] = details

            result = collection.insert_one(doc)
            doc["_id"] = result.inserted_id
            return doc
        except Exception:
            # Fallback for uninitialized DB or testing
            return {
                "user_id": user_id,
                "event": event,
                "ip_address": ip_address or "0.0.0.0",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    @classmethod
    def get_user_logs(cls, user_id: str, limit: int = 20) -> List[Dict[str, Any]]:
        """Retrieve recent security audit logs for a user."""
        try:
            collection = cls.get_collection()
            uid = ObjectId(user_id) if ObjectId.is_valid(user_id) else user_id
            cursor = collection.find({"user_id": uid}).sort("timestamp", -1).limit(limit)
            return list(cursor)
        except Exception:
            return []
