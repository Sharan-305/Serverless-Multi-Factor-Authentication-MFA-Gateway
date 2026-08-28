"""Logout Lambda Handler."""

import json
import logging
from typing import Dict, Any
from backend.utils.response import success_response, error_response
from backend.security.jwt_handler import decode_jwt_token
from backend.database.session_model import SessionModel
from backend.database.audit_model import AuditModel
from backend.functions.register import extract_ip

logger = logging.getLogger(__name__)


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda entry point for user logout and session revocation."""
    try:
        ip_addr = extract_ip(event)
        session_id = None
        user_id = None

        # 1. Try reading from Custom Authorizer context
        auth_context = event.get("requestContext", {}).get("authorizer", {})
        if auth_context:
            session_id = auth_context.get("session_id")
            user_id = auth_context.get("principalId") or auth_context.get("user_id")

        # 2. Fallback: Parse Authorization header directly
        if not session_id:
            headers = event.get("headers") or {}
            auth_header = headers.get("Authorization") or headers.get("authorization")
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1].strip()
                decoded = decode_jwt_token(token)
                if decoded:
                    session_id = decoded.get("session_id")
                    user_id = decoded.get("sub")

        # 3. Revoke Session if session_id found
        if session_id:
            SessionModel.revoke_session(session_id)
            AuditModel.log_event(
                event=AuditModel.EVENT_LOGOUT,
                user_id=user_id,
                ip_address=ip_addr,
                details={"session_id": session_id}
            )
            return success_response(
                data={"session_id": session_id},
                status_code=200,
                message="Logged out successfully. Session has been revoked."
            )
        else:
            return error_response("Invalid or missing session information.", 400)

    except Exception as e:
        logger.error(f"Logout error: {str(e)}", exc_info=True)
        return error_response("An internal error occurred during logout.", 500)
