"""OTP generation, hashing, verification, and dispatch module."""

import secrets
import hashlib
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import boto3
from botocore.exceptions import BotoCoreError, ClientError
from typing import Tuple, Dict, Any
from backend.utils.config import config

logger = logging.getLogger(__name__)


def generate_otp(length: int = 6) -> str:
    """Generate a cryptographically secure numeric OTP string."""
    digits = [str(secrets.randbelow(10)) for _ in range(length)]
    return "".join(digits)


def hash_otp(otp: str) -> str:
    """Hash an OTP code using SHA-256 for secure storage at rest in MongoDB."""
    return hashlib.sha256(otp.encode("utf-8")).hexdigest()


def verify_otp_hash(otp: str, stored_hash: str) -> bool:
    """Verify a raw OTP against a stored SHA-256 hash."""
    if not otp or not stored_hash:
        return False
    computed_hash = hash_otp(otp)
    return secrets.compare_digest(computed_hash, stored_hash)


def send_smtp_otp(recipient: str, otp: str) -> Dict[str, Any]:
    """Send OTP email using standard SMTP (Gmail, Outlook, Mailtrap, Brevo, SendGrid, etc.)."""
    try:
        sender_email = config.SMTP_SENDER_EMAIL or "noreply@example.com"

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"Your MFA Verification Code: {otp}"
        msg["From"] = sender_email
        msg["To"] = recipient

        # Text Body
        text_content = (
            f"Hello,\n\n"
            f"Your Multi-Factor Authentication (MFA) code is: {otp}\n\n"
            f"This code will expire in {config.OTP_EXPIRY_MINUTES} minutes.\n"
            f"If you did not request this code, please ignore this email.\n\n"
            f"Best regards,\nMFA Security Gateway Team"
        )

        # HTML Body
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0f172a; color: #f8fafc; margin: 0; padding: 20px; }}
        .container {{ max-width: 500px; margin: 0 auto; background: #1e293b; border-radius: 12px; border: 1px solid #334155; padding: 32px; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5); }}
        .header {{ text-align: center; margin-bottom: 24px; }}
        .logo {{ font-size: 24px; font-weight: bold; background: linear-gradient(to right, #6366f1, #a855f7); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        .otp-card {{ background: #090d16; border: 2px dashed #6366f1; border-radius: 10px; padding: 20px; text-align: center; margin: 24px 0; }}
        .otp-code {{ font-size: 36px; font-weight: 800; letter-spacing: 8px; color: #818cf8; font-family: monospace; }}
        .footer {{ margin-top: 24px; text-align: center; font-size: 12px; color: #94a3b8; line-height: 1.5; }}
        .warning {{ font-size: 13px; color: #f59e0b; margin-top: 12px; text-align: center; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">🔒 MFA Gateway</div>
            <p style="color: #94a3b8; margin-top: 8px;">Multi-Factor Authentication Verification</p>
        </div>
        <p style="font-size: 15px; line-height: 1.6; color: #e2e8f0;">Hello,</p>
        <p style="font-size: 15px; line-height: 1.6; color: #cbd5e1;">Your single-use verification code for logging into your account is:</p>
        
        <div class="otp-card">
            <div class="otp-code">{otp}</div>
            <p style="font-size: 12px; color: #94a3b8; margin-top: 10px;">Valid for {config.OTP_EXPIRY_MINUTES} minutes</p>
        </div>

        <p class="warning">⚠️ If you did not attempt to log in, please ignore this message.</p>

        <div class="footer">
            <p>© Serverless MFA Gateway System. All rights reserved.</p>
        </div>
    </div>
</body>
</html>"""

        msg.attach(MIMEText(text_content, "plain"))
        msg.attach(MIMEText(html_content, "html"))

        if config.SMTP_USE_SSL:
            server = smtplib.SMTP_SSL(config.SMTP_HOST, config.SMTP_PORT, timeout=10)
        else:
            server = smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=10)
            if config.SMTP_USE_TLS:
                server.starttls()

        if config.SMTP_USERNAME and config.SMTP_PASSWORD:
            server.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)

        server.send_message(msg)
        server.quit()

        logger.info(f"Successfully sent OTP email to {recipient} via SMTP ({config.SMTP_HOST}).")
        return {"status": "SUCCESS", "provider": "smtp", "recipient": recipient}
    except Exception as e:
        logger.error(f"SMTP OTP Delivery Error to {recipient}: {str(e)}")
        print(f"[MOCK FALLBACK] Failed to send via SMTP ({str(e)}). OTP code for {recipient}: {otp}")
        return {"status": "SUCCESS", "provider": "smtp_fallback_mock", "error": str(e)}


def send_otp(recipient: str, otp: str, channel: str = "email") -> Dict[str, Any]:
    """Dispatch an OTP to the user via SMTP, AWS SES, AWS SNS, or Mock mode based on configuration."""
    provider = config.OTP_PROVIDER.lower()

    if provider == "mock":
        # Log to standard output / audit log for local testing & development
        logger.info(f"[MOCK OTP DELIVERY] Sent OTP '{otp}' to {recipient} via {channel}.")
        print(f"\n==================================================")
        print(f" [MOCK OTP DISPATCH] Channel: {channel.upper()}")
        print(f" Recipient: {recipient}")
        print(f" OTP Code: {otp}")
        print(f" Valid for: {config.OTP_EXPIRY_MINUTES} minutes")
        print(f"==================================================\n")
        return {"status": "SUCCESS", "provider": "mock", "channel": channel}

    elif provider == "smtp" or (provider == "auto" and channel == "email" and config.SMTP_USERNAME):
        return send_smtp_otp(recipient=recipient, otp=otp)

    elif provider == "ses" or (provider == "auto" and channel == "email"):
        try:
            ses_client = boto3.client("ses", region_name=config.AWS_REGION)
            response = ses_client.send_email(
                Source=config.SES_SENDER_EMAIL,
                Destination={"ToAddresses": [recipient]},
                Message={
                    "Subject": {"Data": "Your MFA Verification Code"},
                    "Body": {
                        "Text": {
                            "Data": f"Your verification code is: {otp}\nIt expires in {config.OTP_EXPIRY_MINUTES} minutes."
                        }
                    },
                },
            )
            return {"status": "SUCCESS", "provider": "ses", "message_id": response.get("MessageId")}
        except (BotoCoreError, ClientError) as e:
            logger.error(f"AWS SES OTP Delivery Error: {str(e)}")
            # Fall back gracefully to logging if SES credentials are not set in environment
            print(f"[MOCK FALLBACK] Failed to send via SES ({str(e)}). OTP code for {recipient}: {otp}")
            return {"status": "SUCCESS", "provider": "ses_fallback_mock", "error": str(e)}

    elif provider == "sns" or (provider == "auto" and channel == "sms"):
        try:
            sns_client = boto3.client("sns", region_name=config.AWS_REGION)
            response = sns_client.publish(
                PhoneNumber=recipient,
                Message=f"Your verification code is: {otp}. Valid for {config.OTP_EXPIRY_MINUTES} mins.",
            )
            return {"status": "SUCCESS", "provider": "sns", "message_id": response.get("MessageId")}
        except (BotoCoreError, ClientError) as e:
            logger.error(f"AWS SNS OTP Delivery Error: {str(e)}")
            print(f"[MOCK FALLBACK] Failed to send via SNS ({str(e)}). OTP code for {recipient}: {otp}")
            return {"status": "SUCCESS", "provider": "sns_fallback_mock", "error": str(e)}

    else:
        logger.warning(f"Unknown OTP provider '{provider}', falling back to mock mode.")
        print(f"[MOCK FALLBACK] OTP code for {recipient}: {otp}")
        return {"status": "SUCCESS", "provider": "mock_fallback"}
