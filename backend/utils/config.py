"""Configuration module for loading and validating environment variables."""

import os
from typing import Dict, Any
from dotenv import load_dotenv

# Load local .env if present
load_dotenv()


class Config:
    """Application configuration loaded from environment variables."""

    # Serverless & Stage settings
    STAGE: str = os.getenv("STAGE", "dev")
    AWS_REGION: str = os.getenv("AWS_REGION", "us-east-1")

    # MongoDB Atlas settings
    MONGODB_URI: str = os.getenv("MONGODB_URI", "")
    DB_NAME: str = os.getenv("DB_NAME", "mfa_gateway")

    # Security settings
    JWT_SECRET: str = os.getenv(
        "JWT_SECRET", "super-secret-mfa-gateway-jwt-key-change-this-in-production-32chars!"
    )
    JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
    JWT_EXPIRATION_MINUTES: int = int(os.getenv("JWT_EXPIRATION_MINUTES", "60"))

    # OTP settings
    OTP_EXPIRY_MINUTES: int = int(os.getenv("OTP_EXPIRY_MINUTES", "5"))
    MAX_OTP_ATTEMPTS: int = int(os.getenv("MAX_OTP_ATTEMPTS", "3"))
    OTP_PROVIDER: str = os.getenv("OTP_PROVIDER", "mock").lower()

    # Rate Limiting
    RATE_LIMIT_LOGIN_PER_MIN: int = int(os.getenv("RATE_LIMIT_LOGIN_PER_MIN", "5"))
    RATE_LIMIT_OTP_PER_MIN: int = int(os.getenv("RATE_LIMIT_OTP_PER_MIN", "3"))

    # SES/SNS settings
    SES_SENDER_EMAIL: str = os.getenv("SES_SENDER_EMAIL", "noreply@example.com")

    # SMTP Settings (For real email delivery via Gmail, Outlook, Mailtrap, Brevo, SendGrid, etc.)
    SMTP_HOST: str = os.getenv("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USERNAME: str = os.getenv("SMTP_USERNAME", "")
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")
    SMTP_SENDER_EMAIL: str = os.getenv("SMTP_SENDER_EMAIL", os.getenv("SES_SENDER_EMAIL", "noreply@example.com"))
    SMTP_USE_TLS: bool = os.getenv("SMTP_USE_TLS", "true").lower() in ("true", "1", "t", "yes")
    SMTP_USE_SSL: bool = os.getenv("SMTP_USE_SSL", "false").lower() in ("true", "1", "t", "yes")

    @classmethod
    def to_dict(cls) -> Dict[str, Any]:
        """Return configuration as a dictionary (masking secrets)."""
        return {
            "STAGE": cls.STAGE,
            "AWS_REGION": cls.AWS_REGION,
            "DB_NAME": cls.DB_NAME,
            "JWT_ALGORITHM": cls.JWT_ALGORITHM,
            "JWT_EXPIRATION_MINUTES": cls.JWT_EXPIRATION_MINUTES,
            "OTP_EXPIRY_MINUTES": cls.OTP_EXPIRY_MINUTES,
            "MAX_OTP_ATTEMPTS": cls.MAX_OTP_ATTEMPTS,
            "OTP_PROVIDER": cls.OTP_PROVIDER,
            "RATE_LIMIT_LOGIN_PER_MIN": cls.RATE_LIMIT_LOGIN_PER_MIN,
            "RATE_LIMIT_OTP_PER_MIN": cls.RATE_LIMIT_OTP_PER_MIN,
            "SMTP_HOST": cls.SMTP_HOST,
            "SMTP_PORT": cls.SMTP_PORT,
            "SMTP_SENDER_EMAIL": cls.SMTP_SENDER_EMAIL,
            "SMTP_USE_TLS": cls.SMTP_USE_TLS,
            "SMTP_USE_SSL": cls.SMTP_USE_SSL,
            "SMTP_CONFIGURED": bool(cls.SMTP_USERNAME and cls.SMTP_PASSWORD),
        }


config = Config()
