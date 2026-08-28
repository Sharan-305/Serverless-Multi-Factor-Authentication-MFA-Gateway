"""Registration Lambda Handler."""

import json
import re
import logging
from typing import Dict, Any
from backend.utils.response import success_response, error_response
from backend.security.password import hash_password, validate_password_strength
from backend.database.user_model import UserModel
from backend.database.audit_model import AuditModel

logger = logging.getLogger(__name__)


def extract_ip(event: Dict[str, Any]) -> str:
    """Extract client IP address from API Gateway request context."""
    request_context = event.get("requestContext", {})
    identity = request_context.get("identity", {})
    if identity.get("sourceIp"):
        return identity["sourceIp"]
    
    headers = event.get("headers") or {}
    for key in ["X-Forwarded-For", "x-forwarded-for", "X-Real-IP", "x-real-ip"]:
        if key in headers:
            return headers[key].split(",")[0].strip()
    return "127.0.0.1"


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda entry point for user registration."""
    try:
        body_raw = event.get("body")
        if not body_raw:
            return error_response("Request body is required.", 400)

        body = json.loads(body_raw) if isinstance(body_raw, str) else body_raw
        
        username = body.get("username", "").strip()
        name = body.get("name", "").strip()
        email = body.get("email", "").strip()
        password = body.get("password", "")

        # 1. Validation
        if not username or not name or not email or not password:
            return error_response("All fields (username, name, email, password) are required.", 400)

        # Email format check
        email_regex = r"^[\w\.-]+@[\w\.-]+\.\w+$"
        if not re.match(email_regex, email):
            return error_response("Invalid email address format.", 400)

        # Password strength check
        is_strong, pwd_msg = validate_password_strength(password)
        if not is_strong:
            return error_response(pwd_msg, 400)

        # 2. Check Uniqueness
        if UserModel.find_by_username(username):
            return error_response("Username or email is already registered.", 409)

        if UserModel.find_by_email(email):
            return error_response("Username or email is already registered.", 409)

        # 3. Password Hashing & Insertion
        pwd_hash = hash_password(password)
        user_doc = UserModel.create_user(
            username=username,
            name=name,
            email=email,
            password_hash=pwd_hash,
            mfa_enabled=True
        )

        ip_addr = extract_ip(event)
        AuditModel.log_event(
            event=AuditModel.EVENT_REGISTER,
            user_id=str(user_doc["_id"]),
            ip_address=ip_addr,
            details={"username": username, "email": email}
        )

        return success_response(
            data={"user_id": str(user_doc["_id"]), "username": username, "email": email},
            status_code=201,
            message="User registered successfully."
        )

    except json.JSONDecodeError:
        return error_response("Invalid JSON payload.", 400)
    except Exception as e:
        logger.error(f"Registration error: {str(e)}", exc_info=True)
        return error_response("An internal error occurred. Please try again later.", 500)
