"""Standardized response formatting for AWS API Gateway integration."""

import json
from typing import Dict, Any, Optional
from bson import ObjectId
from datetime import datetime


class JSONEncoder(json.JSONEncoder):
    """Custom JSON encoder to convert MongoDB ObjectIds and Datetimes to ISO strings."""

    def default(self, o: Any) -> Any:
        if isinstance(o, ObjectId):
            return str(o)
        if isinstance(o, datetime):
            return o.isoformat()
        return super().default(o)


def build_response(
    status_code: int,
    body: Dict[str, Any],
    headers: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """Construct a standard API Gateway proxy response object with CORS headers."""
    default_headers = {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "Content-Type,Authorization,X-Amz-Date,X-Api-Key,X-Amz-Security-Token",
        "Access-Control-Allow-Methods": "GET,POST,OPTIONS,PUT,DELETE",
    }

    if headers:
        default_headers.update(headers)

    return {
        "statusCode": status_code,
        "headers": default_headers,
        "body": json.dumps(body, cls=JSONEncoder),
    }


def success_response(
    data: Dict[str, Any],
    status_code: int = 200,
    message: Optional[str] = None
) -> Dict[str, Any]:
    """Return a successful API Gateway response."""
    payload = {"success": True}
    if message:
        payload["message"] = message
    payload.update(data)
    return build_response(status_code, payload)


def error_response(
    message: str,
    status_code: int = 400,
    error_code: Optional[str] = None
) -> Dict[str, Any]:
    """Return an error API Gateway response with standardized generic message structure."""
    payload = {
        "success": False,
        "error": message,
    }
    if error_code:
        payload["error_code"] = error_code

    return build_response(status_code, payload)
