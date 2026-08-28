"""Custom AWS API Gateway Lambda Authorizer (Policy Enforcement Point)."""

import logging
from typing import Dict, Any, Optional
from backend.security.jwt_handler import decode_jwt_token
from backend.database.session_model import SessionModel
from backend.database.audit_model import AuditModel

logger = logging.getLogger(__name__)


def generate_policy(
    principal_id: str,
    effect: str,
    resource: str,
    context: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Construct a standard AWS IAM Policy document for API Gateway Authorization response."""
    auth_response: Dict[str, Any] = {"principalId": principal_id}

    if effect and resource:
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": effect,
                    "Resource": resource,
                }
            ],
        }
        auth_response["policyDocument"] = policy_document

    if context:
        # Context values sent to backend Lambda must be primitive strings/integers/booleans
        stringified_context = {k: str(v) for k, v in context.items()}
        auth_response["context"] = stringified_context

    return auth_response


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda Authorizer handler validating JWT token and MongoDB session state."""
    method_arn = event.get("methodArn", "*")

    try:
        # 1. Extract Token from header
        token = None
        if "authorizationToken" in event:
            token = event["authorizationToken"]
        elif "headers" in event and event["headers"]:
            headers = event["headers"]
            token = headers.get("Authorization") or headers.get("authorization")

        if not token:
            logger.warning("Authorizer: Missing Authorization header.")
            return generate_policy("anonymous", "Deny", method_arn)

        if token.startswith("Bearer "):
            token = token.split(" ")[1].strip()

        # 2. Decode and verify JWT signature and expiry
        decoded_claims = decode_jwt_token(token)
        if not decoded_claims:
            logger.warning("Authorizer: Invalid or expired JWT token.")
            return generate_policy("anonymous", "Deny", method_arn)

        user_id = decoded_claims.get("sub")
        username = decoded_claims.get("username", "")
        email = decoded_claims.get("email", "")
        session_id = decoded_claims.get("session_id")

        if not user_id or not session_id:
            logger.warning("Authorizer: JWT claims missing user_id or session_id.")
            return generate_policy("anonymous", "Deny", method_arn)

        # 3. Zero-Trust PEP Check: Verify active session status in MongoDB
        session = SessionModel.find_by_id(session_id)
        if not session:
            logger.warning(f"Authorizer: Session {session_id} not found in database.")
            return generate_policy(user_id, "Deny", method_arn)

        status = session.get("status")
        if status != SessionModel.STATUS_ACTIVE:
            logger.warning(f"Authorizer: Session {session_id} is in status '{status}' (Must be ACTIVE).")
            AuditModel.log_event(
                event=AuditModel.EVENT_UNAUTHORIZED,
                user_id=user_id,
                details={"reason": f"Attempted request with non-active session status '{status}'"}
            )
            return generate_policy(user_id, "Deny", method_arn)

        # 4. Token & Session Valid -> Allow Request
        auth_context = {
            "user_id": user_id,
            "username": username,
            "email": email,
            "session_id": session_id,
        }

        # Use wildcards for resource ARN so cached policy works across all API Gateway routes
        resource_arn = method_arn.split("/")[0] + "/*" if "/" in method_arn else method_arn

        return generate_policy(user_id, "Allow", resource_arn, context=auth_context)

    except Exception as e:
        logger.error(f"Authorizer exception: {str(e)}", exc_info=True)
        return generate_policy("anonymous", "Deny", method_arn)
