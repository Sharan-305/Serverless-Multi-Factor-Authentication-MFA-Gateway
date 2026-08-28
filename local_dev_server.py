"""Local Development & Demonstration Server for Serverless MFA Gateway (HTTPS Enabled).

Serves the frontend static files on https://localhost:8000 and routes
API requests (/dev/*) to the AWS Lambda function handlers locally over SSL/TLS,
including executing the Lambda Authorizer Policy Enforcement Point (PEP).
"""

import os
import json
import ssl
import logging
from http.server import HTTPServer, SimpleHTTPRequestHandler

# Import Lambda handlers
from backend.functions.register import handler as register_handler
from backend.functions.login import handler as login_handler
from backend.functions.send_otp import handler as send_otp_handler
from backend.functions.verify_otp import handler as verify_otp_handler
from backend.functions.logout import handler as logout_handler
from backend.functions.authorizer import handler as authorizer_handler
from backend.functions.dashboard_data import handler as dashboard_data_handler

from backend.database.mongodb import get_database, set_database
import mongomock
from generate_cert import generate_self_signed_cert

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s - %(message)s')
logger = logging.getLogger("LocalDevServer")

# Auto-initialize in-memory MongoDB fallback if real MongoDB Atlas URI is unconfigured
if get_database() is None:
    mock_client = mongomock.MongoClient()
    set_database(mock_client["mfa_gateway"])
    logger.info("LocalDevServer: Initialized in-memory mongomock fallback database.")

FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "frontend")


class DevServerHandler(SimpleHTTPRequestHandler):
    """Custom request handler bridging local HTTPS to Lambda handlers and serving static frontend."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=FRONTEND_DIR, **kwargs)

    def do_OPTIONS(self):
        """Handle CORS preflight requests."""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def _build_lambda_event(self, path: str, method: str):
        """Build API Gateway Proxy Event dictionary from HTTP request."""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else ""

        headers = {k: v for k, v in self.headers.items()}

        return {
            "path": path,
            "httpMethod": method,
            "headers": headers,
            "body": body,
            "requestContext": {
                "identity": {
                    "sourceIp": self.client_address[0]
                }
            }
        }

    def _send_lambda_response(self, lambda_res: dict):
        """Translate Lambda response dictionary to HTTP response."""
        status_code = lambda_res.get("statusCode", 500)
        headers = lambda_res.get("headers", {})
        body = lambda_res.get("body", "{}")

        self.send_response(status_code)
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def do_POST(self):
        """Route POST requests to Lambda functions."""
        path = self.path.split("?")[0]
        logger.info(f"POST request to {path}")

        event = self._build_lambda_event(path, "POST")

        if path == "/dev/register":
            res = register_handler(event, None)
            self._send_lambda_response(res)

        elif path == "/dev/login":
            res = login_handler(event, None)
            self._send_lambda_response(res)

        elif path == "/dev/send-otp":
            res = send_otp_handler(event, None)
            self._send_lambda_response(res)

        elif path == "/dev/verify-otp":
            res = verify_otp_handler(event, None)
            self._send_lambda_response(res)

        elif path == "/dev/logout":
            # 1. Run Custom Lambda Authorizer (PEP)
            auth_event = {
                "authorizationToken": self.headers.get("Authorization", ""),
                "methodArn": f"arn:aws:execute-api:local:000000000000:local/dev/POST/logout"
            }
            policy = authorizer_handler(auth_event, None)
            effect = policy.get("policyDocument", {}).get("Statement", [{}])[0].get("Effect")

            if effect != "Allow":
                logger.warning("PEP Denied access to /dev/logout")
                self._send_lambda_response({
                    "statusCode": 403,
                    "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
                    "body": json.dumps({"success": False, "error": "Access Denied by Policy Enforcement Point (Authorizer)."})
                })
                return

            event["requestContext"]["authorizer"] = policy.get("context", {})
            res = logout_handler(event, None)
            self._send_lambda_response(res)

        else:
            self.send_error(404, "Endpoint Not Found")

    def do_GET(self):
        """Route GET requests to Lambda functions or serve static files."""
        path = self.path.split("?")[0]

        if path == "/dev/dashboard-data":
            logger.info("GET request to /dev/dashboard-data (Executing Lambda Authorizer PEP...)")
            # 1. Run Custom Lambda Authorizer (PEP)
            auth_event = {
                "authorizationToken": self.headers.get("Authorization", ""),
                "methodArn": f"arn:aws:execute-api:local:000000000000:local/dev/GET/dashboard-data"
            }
            policy = authorizer_handler(auth_event, None)
            effect = policy.get("policyDocument", {}).get("Statement", [{}])[0].get("Effect")

            if effect != "Allow":
                logger.warning("PEP Denied access to /dev/dashboard-data")
                self._send_lambda_response({
                    "statusCode": 403,
                    "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
                    "body": json.dumps({"success": False, "error": "Access Denied by Policy Enforcement Point (Authorizer)."})
                })
                return

            event = self._build_lambda_event(path, "GET")
            event["requestContext"]["authorizer"] = policy.get("context", {})
            res = dashboard_data_handler(event, None)
            self._send_lambda_response(res)
        else:
            # Fallback to static file server
            super().do_GET()


def main():
    cert_file = "cert.pem"
    key_file = "key.pem"

    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        generate_self_signed_cert(cert_file, key_file)

    port = 8000
    server_address = ("", port)
    httpd = HTTPServer(server_address, DevServerHandler)

    # Wrap HTTPServer with SSL Context
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    httpd.socket = ssl_context.wrap_socket(httpd.socket, server_side=True)

    print("\n==========================================================")
    print(" [HTTPS SERVER] Serverless MFA Gateway Secure Dev Server")
    print("==========================================================")
    print(f" Web Interface (HTTPS): https://localhost:{port}")
    print(f" Secure API Endpoints:  https://localhost:{port}/dev/*")
    print(f" Policy Check:          Active (Custom Lambda Authorizer PEP)")
    print("==========================================================\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping HTTPS local server...")
        httpd.server_close()


if __name__ == "__main__":
    main()
