# Serverless Multi-Factor Authentication (MFA) Gateway

> A production-grade Serverless MFA Gateway built with **AWS API Gateway**, **AWS Lambda (Python 3.12)**, **MongoDB Atlas**, **PyJWT**, **Bcrypt**, and **Serverless Framework**.

This application implements a **Zero-Trust Policy Enforcement Point (PEP)** pattern. All incoming requests to protected routes pass through a custom AWS Lambda Authorizer that validates JWT signatures, token expiration, and database session statuses in real time before granting access to downstream microservices.

---

## 🏛️ Architecture Overview

```text
USER → Frontend (HTML/CSS/JS) → API Gateway (REST API / PEP)
                                       │
                       ┌───────────────┼────────────────┐
                       ▼               ▼                ▼
                 Register Lambda  Login Lambda    MFA/OTP Lambda
                       │               │                │
                       └───────────────┼────────────────┘
                                       ▼
                               MongoDB Atlas
                        (users / sessions / audit_logs)
                                       │
                                       ▼
                       OTP Delivery (SMTP / SES / SNS / Mock)
```

### Database Schema (Database: `mfa_gateway`)

- **`users`**: User records with unique `username` and `email`, bcrypt `password_hash`, `mfa_enabled` boolean, and timestamps.
- **`sessions`**: Active session and OTP state records storing `user_id`, `otp_hash` (SHA-256), `expires_at`, `attempts` count, `status` (`PENDING_MFA` | `ACTIVE` | `EXPIRED` | `REVOKED`), and issued `token`.
- **`audit_logs`**: Immutable security event logs tracking `user_id`, `event` type (`LOGIN_SUCCESS`, `LOGIN_FAIL`, `OTP_SENT`, `OTP_VERIFIED`, `OTP_LOCKOUT`, `LOGOUT`, `UNAUTHORIZED_ACCESS`), client `ip_address`, and ISO timestamp.

---

## 📁 Repository Structure

```text
serverless-mfa-gateway/
├── frontend/
│   ├── index.html            # Landing page
│   ├── login.html            # User login form
│   ├── register.html         # User registration form
│   ├── verify.html           # 6-Digit OTP verification interface
│   ├── dashboard.html        # Protected user dashboard & audit log view
│   ├── css/
│   │   └── style.css         # Modern glassmorphic dark theme stylesheet
│   └── js/
│       ├── login.js          # Credential submission & MFA redirect
│       ├── register.js       # Input validation & registration handler
│       ├── verify.js         # PIN box auto-advance & OTP submission
│       └── dashboard.js      # PEP authorization check & logout logic
├── backend/
│   ├── functions/
│   │   ├── register.py       # User registration handler
│   │   ├── login.py          # Credential check & OTP issuance handler
│   │   ├── send_otp.py       # OTP generation & resend handler
│   │   ├── verify_otp.py     # OTP verification & JWT issuance handler
│   │   ├── logout.py         # Session revocation handler
│   │   ├── authorizer.py     # PEP Custom AWS Lambda Authorizer
│   │   └── dashboard_data.py # Protected profile & audit data handler
│   ├── database/
│   │   ├── mongodb.py        # MongoClient pooling across Lambda warm starts
│   │   ├── user_model.py     # User document DAO
│   │   ├── session_model.py  # Session & OTP state DAO
│   │   └── audit_model.py    # Audit logging DAO
│   ├── security/
│   │   ├── password.py       # Bcrypt hashing & strength validator
│   │   ├── jwt_handler.py    # PyJWT token generation & decode
│   │   ├── otp_handler.py    # Cryptographic OTP generator & SES/SNS dispatcher
│   │   └── rate_limiter.py   # Distributed rate limiter
│   └── utils/
│       ├── config.py         # Environment variable loader
│       └── response.py       # API Gateway proxy response builder & CORS
├── infrastructure/
│   ├── api-gateway.yml       # API Gateway CORS responses
│   ├── lambda.yml            # Shared Lambda runtime defaults
│   └── iam.yml               # Least-privilege IAM policies
├── tests/
│   ├── test_register.py      # Registration unit tests
│   ├── test_login.py         # Login unit tests
│   ├── test_otp.py           # OTP generation & verification unit tests
│   ├── test_authorizer.py    # Custom Lambda authorizer unit tests
│   └── test_logout.py        # Logout & session revocation unit tests
├── requirements.txt          # Python dependencies
├── serverless.yml            # Serverless Framework IaC configuration
├── .env.example              # Environment variables template
├── .gitignore                # Git ignore configuration
└── README.md                 # Project documentation
```

---

## ⚙️ Environment Configuration

Copy `.env.example` to `.env` and update the required values:

```bash
cp .env.example .env
```

| Key | Default / Sample | Description |
|---|---|---|
| `STAGE` | `dev` | Serverless deployment stage |
| `AWS_REGION` | `us-east-1` | Target AWS region |
| `MONGODB_URI` | `mongodb+srv://...` | MongoDB Atlas cluster URI |
| `DB_NAME` | `mfa_gateway` | Database name |
| `JWT_SECRET` | `32-char-random-string` | Secret key for JWT signing |
| `JWT_ALGORITHM` | `HS256` | JWT signing algorithm |
| `JWT_EXPIRATION_MINUTES` | `60` | JWT token validity duration |
| `OTP_EXPIRY_MINUTES` | `5` | OTP code lifespan |
| `MAX_OTP_ATTEMPTS` | `3` | Max failed attempts before lockout |
| `OTP_PROVIDER` | `mock` | Delivery mode (`mock` \| `smtp` \| `ses` \| `sns` \| `auto`) |
| `SMTP_HOST` | `smtp.gmail.com` | SMTP host address |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USERNAME` | `your_email@gmail.com` | SMTP account email |
| `SMTP_PASSWORD` | `your_app_password` | SMTP App password |

---

## 🧪 Local Testing & Verification

1. **Create Virtual Environment & Install Dependencies:**
   ```bash
   python -m venv venv
   # On Windows PowerShell:
   .\venv\Scripts\Activate.ps1
   # On Linux/macOS:
   source venv/bin/activate

   pip install -r requirements.txt
   ```

2. **Run Pytest Test Suite:**
   ```bash
   pytest -v --tb=short
   ```

3. **Serve Frontend Locally:**
   ```bash
   python local_dev_server.py
   ```
   Open `https://localhost:8000` in your web browser.

---

## 🚀 AWS Deployment with Serverless Framework

1. **Install Serverless Framework CLI:**
   ```bash
   npm install -g serverless
   ```

2. **Deploy to AWS:**
   ```bash
   serverless deploy --stage dev
   ```

3. **Deploy Output:**
   Serverless will output your API Gateway base URL:
   ```text
   endpoints:
     POST - https://<api-id>.execute-api.us-east-1.amazonaws.com/dev/register
     POST - https://<api-id>.execute-api.us-east-1.amazonaws.com/dev/login
     POST - https://<api-id>.execute-api.us-east-1.amazonaws.com/dev/send-otp
     POST - https://<api-id>.execute-api.us-east-1.amazonaws.com/dev/verify-otp
     POST - https://<api-id>.execute-api.us-east-1.amazonaws.com/dev/logout
     GET  - https://<api-id>.execute-api.us-east-1.amazonaws.com/dev/dashboard-data
   ```

---

## 🔒 Security Features Checklist

- [x] **Zero-Trust PEP Layer:** Custom Lambda authorizer intercepts and validates JWTs + live session state in MongoDB Atlas before request reaches backend handlers.
- [x] **Bcrypt Password Hashing:** Salted bcrypt hashing with strength verification.
- [x] **Secure OTP Storage:** OTPs hashed with SHA-256 before persistence; raw codes never stored in plain text.
- [x] **Attempt Capping & Lockout:** Sessions locked out after exceeding max attempt limit.
- [x] **Session Revocation:** Logout immediately invalidates tokens in MongoDB rather than relying solely on JWT expiry.
- [x] **Audit Trail:** Immutable logging of security events with IP tracking.
- [x] **Rate Limiting:** Distributed rate limiting per client IP / user.
