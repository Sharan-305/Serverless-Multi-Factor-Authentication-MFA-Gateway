"""User model for MongoDB 'users' collection operations."""

from datetime import datetime, timezone
from typing import Optional, Dict, Any
from bson import ObjectId
from backend.database.mongodb import get_database


class UserModel:
    """Data Access Object for User documents."""

    @staticmethod
    def get_collection():
        """Retrieve MongoDB users collection."""
        db = get_database()
        if db is None:
            raise RuntimeError("Database connection not initialized")
        return db["users"]

    @classmethod
    def find_by_username(cls, username: str) -> Optional[Dict[str, Any]]:
        """Look up user by unique username (case-insensitive search)."""
        collection = cls.get_collection()
        return collection.find_one({"username": {"$regex": f"^{username}$", "$options": "i"}})

    @classmethod
    def find_by_email(cls, email: str) -> Optional[Dict[str, Any]]:
        """Look up user by unique email (case-insensitive search)."""
        collection = cls.get_collection()
        return collection.find_one({"email": {"$regex": f"^{email}$", "$options": "i"}})

    @classmethod
    def find_by_id(cls, user_id: str) -> Optional[Dict[str, Any]]:
        """Look up user by ObjectId."""
        collection = cls.get_collection()
        try:
            return collection.find_one({"_id": ObjectId(user_id)})
        except Exception:
            return None

    @classmethod
    def create_user(
        cls,
        username: str,
        name: str,
        email: str,
        password_hash: str,
        mfa_enabled: bool = True
    ) -> Dict[str, Any]:
        """Insert a new user document."""
        collection = cls.get_collection()
        user_doc = {
            "username": username.strip().lower(),
            "name": name.strip(),
            "email": email.strip().lower(),
            "password_hash": password_hash,
            "mfa_enabled": mfa_enabled,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        result = collection.insert_one(user_doc)
        user_doc["_id"] = result.inserted_id
        return user_doc

    @classmethod
    def update_mfa_status(cls, user_id: str, enabled: bool) -> bool:
        """Update MFA enabled status for a user."""
        collection = cls.get_collection()
        try:
            res = collection.update_one(
                {"_id": ObjectId(user_id)},
                {"$set": {"mfa_enabled": enabled}}
            )
            return res.modified_count > 0
        except Exception:
            return False
