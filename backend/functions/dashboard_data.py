"""Dashboard Data Protected Lambda Handler."""

import logging
from typing import Dict, Any
from backend.utils.response import success_response, error_response
from backend.database.user_model import UserModel
from backend.database.session_model import SessionModel
from backend.database.audit_model import AuditModel

logger = logging.getLogger(__name__)


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Protected Lambda handler returning user profile and security audit log history."""
    try:
        # Extract authorizer context injected by PEP Lambda Authorizer
        auth_context = event.get("requestContext", {}).get("authorizer", {})
        user_id = auth_context.get("user_id") or auth_context.get("principalId")
        session_id = auth_context.get("session_id")

        if not user_id:
            return error_response("Unauthorized access. User context missing.", 401)

        user = UserModel.find_by_id(user_id)
        if not user:
            return error_response("User profile not found.", 404)

        session = SessionModel.find_by_id(session_id) if session_id else None
        audit_logs = AuditModel.get_user_logs(user_id, limit=20)

        # Sanitize user payload
        profile = {
            "user_id": str(user["_id"]),
            "username": user["username"],
            "name": user.get("name", ""),
            "email": user["email"],
            "mfa_enabled": user.get("mfa_enabled", True),
            "created_at": user.get("created_at"),
        }

        session_info = {
            "session_id": session_id,
            "status": session.get("status") if session else "ACTIVE",
            "expires_at": session.get("expires_at") if session else None,
        }

        # Sanitize audit log ObjectIds for JSON output
        sanitized_logs = []
        for log in audit_logs:
            sanitized_logs.append({
                "id": str(log.get("_id", "")),
                "event": log.get("event"),
                "ip_address": log.get("ip_address"),
                "timestamp": log.get("timestamp"),
                "details": log.get("details", {}),
            })

        return success_response(
            data={
                "user": profile,
                "session": session_info,
                "audit_logs": sanitized_logs,
            },
            status_code=200,
            message="Dashboard data retrieved successfully."
        )

    except Exception as e:
        logger.error(f"Dashboard data error: {str(e)}", exc_info=True)
        return error_response("An internal error occurred while loading dashboard data.", 500)
