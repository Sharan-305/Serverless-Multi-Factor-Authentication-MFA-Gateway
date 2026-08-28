"""Login Lambda Handler."""

import json
import logging
from typing import Dict, Any
from backend.utils.response import success_response, error_response
from backend.utils.config import config
from backend.security.password import verify_password
from backend.security.otp_handler import generate_otp, hash_otp, send_otp
from backend.security.rate_limiter import check_rate_limit
from backend.database.user_model import UserModel
from backend.database.session_model import SessionModel
from backend.database.audit_model import AuditModel
from backend.functions.register import extract_ip

logger = logging.getLogger(__name__)


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda entry point for user login & OTP trigger."""
    try:
        ip_addr = extract_ip(event)

        # 1. Rate Limiting Check
        allowed, remaining = check_rate_limit(
            identifier=ip_addr,
            action="login",
            max_requests=config.RATE_LIMIT_LOGIN_PER_MIN,
            window_seconds=60
        )
        if not allowed:
            AuditModel.log_event(
                event=AuditModel.EVENT_UNAUTHORIZED,
                ip_address=ip_addr,
                details={"reason": "Login rate limit exceeded"}
            )
            return error_response("Too many login attempts. Please try again later.", 429)

        body_raw = event.get("body")
        if not body_raw:
            return error_response("Request body is required.", 400)

        body = json.loads(body_raw) if isinstance(body_raw, str) else body_raw
        username = body.get("username", "").strip()
        password = body.get("password", "")

        if not username or not password:
            return error_response("Username and password are required.", 400)

        # 2. Look up User
        user = UserModel.find_by_username(username)
        if not user:
            # Generic error to prevent user enumeration
            AuditModel.log_event(
                event=AuditModel.EVENT_LOGIN_FAIL,
                ip_address=ip_addr,
                details={"attempted_username": username, "reason": "User not found"}
            )
            return error_response("Invalid username or password.", 401)

        # 3. Verify Password
        if not verify_password(password, user["password_hash"]):
            AuditModel.log_event(
                event=AuditModel.EVENT_LOGIN_FAIL,
                user_id=str(user["_id"]),
                ip_address=ip_addr,
                details={"reason": "Incorrect password"}
            )
            return error_response("Invalid username or password.", 401)

        # 4. Generate OTP & Create Pending Session
        raw_otp = generate_otp(6)
        hashed_otp = hash_otp(raw_otp)

        session = SessionModel.create_otp_session(
            user_id=str(user["_id"]),
            otp_hash=hashed_otp,
            expiry_minutes=config.OTP_EXPIRY_MINUTES
        )
        session_id = str(session["_id"])

        # 5. Dispatch OTP via Email/SMS/Mock
        recipient = user.get("email")
        send_result = send_otp(recipient=recipient, otp=raw_otp, channel="email")

        # 6. Audit Logging
        AuditModel.log_event(
            event=AuditModel.EVENT_LOGIN_SUCCESS,
            user_id=str(user["_id"]),
            ip_address=ip_addr,
            details={"session_id": session_id}
        )
        AuditModel.log_event(
            event=AuditModel.EVENT_OTP_SENT,
            user_id=str(user["_id"]),
            ip_address=ip_addr,
            details={"session_id": session_id, "provider": send_result.get("provider")}
        )

        return success_response(
            data={
                "mfa_required": True,
                "session_id": session_id,
                "user_id": str(user["_id"]),
                "username": user["username"],
                "email": user["email"],
                "expires_in_seconds": config.OTP_EXPIRY_MINUTES * 60,
                # Include debug_otp in non-production / mock mode for easy API testing
                **({"debug_otp": raw_otp} if config.OTP_PROVIDER in ["mock", "dev"] or config.STAGE == "dev" else {})
            },
            status_code=200,
            message="Credentials verified. OTP sent to your registered email."
        )

    except json.JSONDecodeError:
        return error_response("Invalid JSON payload.", 400)
    except Exception as e:
        logger.error(f"Login error: {str(e)}", exc_info=True)
        return error_response("An internal error occurred. Please try again later.", 500)
