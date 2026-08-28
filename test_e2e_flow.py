"""End-to-End Mock Execution Test Script for Serverless MFA Gateway."""

import json
import mongomock
from backend.database.mongodb import set_database
from backend.functions.register import handler as register_handler
from backend.functions.login import handler as login_handler
from backend.functions.send_otp import handler as send_otp_handler
from backend.functions.verify_otp import handler as verify_otp_handler
from backend.functions.authorizer import handler as authorizer_handler
from backend.functions.dashboard_data import handler as dashboard_data_handler
from backend.functions.logout import handler as logout_handler


def run_mock_demo():
    print("==========================================================================")
    print(" [MOCK E2E] SERVERLESS MFA GATEWAY - MOCK END-TO-END FLOW SIMULATION")
    print("==========================================================================")

    # 1. Setup in-memory MongoDB mock
    client = mongomock.MongoClient()
    db = client["mfa_gateway"]
    set_database(db)
    print("\n[STEP 1] In-memory MongoDB Atlas database initialized.")

    # 2. Register a new user
    print("\n[STEP 2] Registering user 'alice_sec'...")
    reg_event = {
        "body": json.dumps({
            "username": "alice_sec",
            "name": "Alice Security",
            "email": "alice@example.com",
            "password": "SecurePassword123!"
        }),
        "requestContext": {"identity": {"sourceIp": "198.51.100.42"}}
    }
    reg_res = register_handler(reg_event, None)
    print(f" -> Status: {reg_res['statusCode']}")
    print(f" -> Response: {reg_res['body']}")

    # 3. User Login
    print("\n[STEP 3] User submitting credentials to /login...")
    login_event = {
        "body": json.dumps({
            "username": "alice_sec",
            "password": "SecurePassword123!"
        }),
        "requestContext": {"identity": {"sourceIp": "198.51.100.42"}}
    }
    login_res = login_handler(login_event, None)
    login_data = json.loads(login_res["body"])
    print(f" -> Status: {login_res['statusCode']}")
    print(f" -> Session ID: {login_data.get('session_id')}")
    print(f" -> MFA Required: {login_data.get('mfa_required')}")

    session_id = login_data["session_id"]

    # Retrieve generated OTP from database for simulation
    session_doc = db["sessions"].find_one({"_id": mongomock.ObjectId(session_id)})
    debug_otp = login_data.get("debug_otp", "Retrieved from session")
    print(f" -> Dispatched OTP Code: {debug_otp}")

    # 4. Verify OTP Code
    print("\n[STEP 4] Submitting 6-digit OTP to /verify-otp...")
    verify_event = {
        "body": json.dumps({
            "session_id": session_id,
            "otp": debug_otp
        }),
        "requestContext": {"identity": {"sourceIp": "198.51.100.42"}}
    }
    verify_res = verify_otp_handler(verify_event, None)
    verify_data = json.loads(verify_res["body"])
    print(f" -> Status: {verify_res['statusCode']}")
    jwt_token = verify_data.get("token")
    print(f" -> Issued Bearer JWT Token: {jwt_token[:35]}...")

    # 5. Policy Enforcement Point (Custom Lambda Authorizer) Check
    print("\n[STEP 5] Invoking Custom Lambda Authorizer PEP on protected route /dashboard-data...")
    auth_event = {
        "authorizationToken": f"Bearer {jwt_token}",
        "methodArn": "arn:aws:execute-api:us-east-1:123456789012:api123/dev/GET/dashboard-data"
    }
    auth_res = authorizer_handler(auth_event, None)
    effect = auth_res["policyDocument"]["Statement"][0]["Effect"]
    print(f" -> Policy Enforcement Result: {effect}")
    print(f" -> Authorizer Context: {json.dumps(auth_res.get('context', {}))}")

    # 6. Fetch Protected Dashboard Data
    print("\n[STEP 6] Accessing protected route /dashboard-data with PEP authorization context...")
    dash_event = {
        "requestContext": {
            "authorizer": auth_res.get("context", {})
        }
    }
    dash_res = dashboard_data_handler(dash_event, None)
    dash_data = json.loads(dash_res["body"])
    print(f" -> User Profile: {dash_data.get('user')}")
    print(f" -> Audit Log Events Recorded: {len(dash_data.get('audit_logs', []))}")
    for log in dash_data.get("audit_logs", []):
        print(f"    - Event: {log['event']} | IP: {log['ip_address']} | Time: {log['timestamp']}")

    # 7. Revoke Session via Logout
    print("\n[STEP 7] Logging out to revoke session...")
    logout_event = {
        "headers": {"Authorization": f"Bearer {jwt_token}"},
        "requestContext": {
            "authorizer": auth_res.get("context", {})
        }
    }
    logout_res = logout_handler(logout_event, None)
    print(f" -> Logout Status: {logout_res['statusCode']}")

    # 8. Verify Policy Enforcement Point Denies Revoked Session Token
    print("\n[STEP 8] Re-invoking Lambda Authorizer PEP with revoked token...")
    auth_res_after = authorizer_handler(auth_event, None)
    effect_after = auth_res_after["policyDocument"]["Statement"][0]["Effect"]
    print(f" -> Policy Enforcement Result (Post-Logout): {effect_after}")
    assert effect_after == "Deny", "PEP must deny access for revoked sessions!"

    print("\n==========================================================================")
    print(" [OK] ZERO-TRUST MOCK FLOW EXECUTED SUCCESSFULLY")
    print("==========================================================================")


if __name__ == "__main__":
    run_mock_demo()
