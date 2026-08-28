"""Verify OTP Lambda Handler."""

import json
import logging
from typing import Dict, Any
from datetime import datetime, timezone
from backend.utils.response import success_response, error_response
from backend.utils.config import config
from backend.security.otp_handler import verify_otp_hash
from backend.security.jwt_handler import generate_jwt_token
from backend.database.user_model import UserModel
from backend.database.session_model import SessionModel
from backend.database.audit_model import AuditModel
from backend.functions.register import extract_ip

logger = logging.getLogger(__name__)


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda entry point for OTP verification and JWT token issuance."""
    try:
        ip_addr = extract_ip(event)

        body_raw = event.get("body")
        if not body_raw:
            return error_response("Request body is required.", 400)

        body = json.loads(body_raw) if isinstance(body_raw, str) else body_raw
        session_id = body.get("session_id")
        otp = body.get("otp", "").strip()

        if not session_id or not otp:
            return error_response("session_id and otp are required.", 400)

        # 1. Fetch Session
        session = SessionModel.find_by_id(session_id)
        if not session:
            return error_response("Invalid or non-existent session.", 404)

        user_id_str = str(session["user_id"])

        # Check Revoked Status
        if session.get("status") == SessionModel.STATUS_REVOKED:
            AuditModel.log_event(
                event=AuditModel.EVENT_UNAUTHORIZED,
                user_id=user_id_str,
                ip_address=ip_addr,
                details={"reason": "Attempted OTP check on revoked session", "session_id": session_id}
            )
            return error_response("Session has been revoked. Please log in again.", 403)

        # 2. Check Expiry
        expires_at_str = session.get("expires_at")
        if expires_at_str:
            expires_at = datetime.fromisoformat(expires_at_str)
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            if now > expires_at:
                SessionModel.mark_expired(session_id)
                AuditModel.log_event(
                    event=AuditModel.EVENT_OTP_FAILED,
                    user_id=user_id_str,
                    ip_address=ip_addr,
                    details={"reason": "Expired OTP", "session_id": session_id}
                )
                return error_response("OTP verification code has expired. Please request a new code.", 400)

        # 3. Check Attempt Threshold
        attempts = session.get("attempts", 0)
        if attempts >= config.MAX_OTP_ATTEMPTS:
            SessionModel.mark_expired(session_id)
            AuditModel.log_event(
                event=AuditModel.EVENT_OTP_LOCKOUT,
                user_id=user_id_str,
                ip_address=ip_addr,
                details={"reason": "Max attempts exceeded", "session_id": session_id}
            )
            return error_response(
                f"Maximum verification attempts ({config.MAX_OTP_ATTEMPTS}) exceeded. Session locked out.",
                429
            )

        # 4. Verify OTP Hash
        stored_hash = session.get("otp_hash")
        if not stored_hash or not verify_otp_hash(otp, stored_hash):
            new_attempts = SessionModel.increment_attempts(session_id)
            remaining = max(0, config.MAX_OTP_ATTEMPTS - new_attempts)

            AuditModel.log_event(
                event=AuditModel.EVENT_OTP_FAILED,
                user_id=user_id_str,
                ip_address=ip_addr,
                details={"attempts": new_attempts, "session_id": session_id}
            )

            if new_attempts >= config.MAX_OTP_ATTEMPTS:
                SessionModel.mark_expired(session_id)
                return error_response("Invalid OTP code. Maximum verification attempts exceeded.", 429)

            return error_response(f"Invalid OTP code. {remaining} attempt(s) remaining.", 400)

        # 5. Successful Verification -> Fetch User info & Issue JWT
        user = UserModel.find_by_id(user_id_str)
        if not user:
            return error_response("User associated with session not found.", 404)

        jwt_token = generate_jwt_token(
            user_id=user_id_str,
            username=user["username"],
            email=user["email"],
            session_id=session_id,
            expiry_minutes=config.JWT_EXPIRATION_MINUTES
        )

        # 6. Activate Session
        SessionModel.activate_session(session_id, jwt_token)

        # 7. Audit Log
        AuditModel.log_event(
            event=AuditModel.EVENT_OTP_VERIFIED,
            user_id=user_id_str,
            ip_address=ip_addr,
            details={"session_id": session_id}
        )

        return success_response(
            data={
                "token": jwt_token,
                "token_type": "Bearer",
                "expires_in_minutes": config.JWT_EXPIRATION_MINUTES,
                "user": {
                    "id": user_id_str,
                    "username": user["username"],
                    "name": user.get("name", ""),
                    "email": user["email"],
                }
            },
            status_code=200,
            message="MFA authentication successful."
        )

    except json.JSONDecodeError:
        return error_response("Invalid JSON payload.", 400)
    except Exception as e:
        logger.error(f"Verify OTP error: {str(e)}", exc_info=True)
        return error_response("An internal error occurred. Please try again later.", 500)
