"""JWT generation and verification module using PyJWT."""

import jwt
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
from backend.utils.config import config


def generate_jwt_token(
    user_id: str,
    username: str,
    email: str,
    session_id: str,
    expiry_minutes: Optional[int] = None
) -> str:
    """Generate a signed JWT token containing user identity and session ID claims."""
    if expiry_minutes is None:
        expiry_minutes = config.JWT_EXPIRATION_MINUTES

    now = datetime.now(timezone.utc)
    expiration = now + timedelta(minutes=expiry_minutes)

    payload = {
        "sub": user_id,
        "username": username,
        "email": email,
        "session_id": session_id,
        "iat": int(now.timestamp()),
        "exp": int(expiration.timestamp()),
        "iss": "mfa-gateway",
    }

    token = jwt.encode(
        payload,
        config.JWT_SECRET,
        algorithm=config.JWT_ALGORITHM
    )
    return token


def decode_jwt_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode and verify a JWT token signature and expiry. Returns payload dictionary if valid, None if invalid or expired."""
    try:
        payload = jwt.decode(
            token,
            config.JWT_SECRET,
            algorithms=[config.JWT_ALGORITHM],
            issuer="mfa-gateway"
        )
        return payload
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None
