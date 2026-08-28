"""Send / Resend OTP Lambda Handler."""

import json
import logging
from typing import Dict, Any
from datetime import datetime, timedelta, timezone
from backend.utils.response import success_response, error_response
from backend.utils.config import config
from backend.security.otp_handler import generate_otp, hash_otp, send_otp
from backend.security.rate_limiter import check_rate_limit
from backend.database.user_model import UserModel
from backend.database.session_model import SessionModel
from backend.database.audit_model import AuditModel
from backend.functions.register import extract_ip

logger = logging.getLogger(__name__)


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda entry point for triggering or resending an OTP code."""
    try:
        ip_addr = extract_ip(event)

        body_raw = event.get("body")
        if not body_raw:
            return error_response("Request body is required.", 400)

        body = json.loads(body_raw) if isinstance(body_raw, str) else body_raw
        session_id = body.get("session_id")
        user_id = body.get("user_id")

        if not session_id and not user_id:
            return error_response("Either session_id or user_id is required.", 400)

        # Look up session
        session = None
        if session_id:
            session = SessionModel.find_by_id(session_id)
        elif user_id:
            session = SessionModel.find_active_session_for_user(user_id)

        if not session:
            return error_response("Session not found or expired.", 404)

        if session.get("status") == SessionModel.STATUS_REVOKED:
            return error_response("Session has been revoked.", 403)

        user_id_str = str(session["user_id"])
        user = UserModel.find_by_id(user_id_str)
        if not user:
            return error_response("User associated with session not found.", 404)

        # Rate Limiting per User / IP
        allowed, remaining = check_rate_limit(
            identifier=user_id_str,
            action="send_otp",
            max_requests=config.RATE_LIMIT_OTP_PER_MIN,
            window_seconds=60
        )
        if not allowed:
            return error_response("OTP resend rate limit exceeded. Please wait before requesting another code.", 429)

        # Generate new OTP & Update session
        raw_otp = generate_otp(6)
        hashed_otp = hash_otp(raw_otp)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=config.OTP_EXPIRY_MINUTES)

        collection = SessionModel.get_collection()
        collection.update_one(
            {"_id": session["_id"]},
            {
                "$set": {
                    "otp_hash": hashed_otp,
                    "expires_at": expires_at.isoformat(),
                    "attempts": 0,
                    "status": SessionModel.STATUS_PENDING
                }
            }
        )

        # Send OTP
        send_result = send_otp(recipient=user["email"], otp=raw_otp, channel="email")

        # Audit log
        AuditModel.log_event(
            event=AuditModel.EVENT_OTP_SENT,
            user_id=user_id_str,
            ip_address=ip_addr,
            details={"session_id": str(session["_id"]), "reason": "resend"}
        )

        return success_response(
            data={
                "session_id": str(session["_id"]),
                "expires_in_seconds": config.OTP_EXPIRY_MINUTES * 60,
                **({"debug_otp": raw_otp} if config.OTP_PROVIDER in ["mock", "dev"] or config.STAGE == "dev" else {})
            },
            status_code=200,
            message="New OTP code has been dispatched."
        )

    except json.JSONDecodeError:
        return error_response("Invalid JSON payload.", 400)
    except Exception as e:
        logger.error(f"Send OTP error: {str(e)}", exc_info=True)
        return error_response("An internal error occurred. Please try again later.", 500)
