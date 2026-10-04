import os
import secrets
import smtplib
import time
from email.message import EmailMessage
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, EmailStr, Field

from backend.database.database import authenticate_user, register_user

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

router = APIRouter()
OTP_TTL_SECONDS = 300
AUTH_SESSION_TTL_SECONDS = 8 * 60 * 60
PENDING_OTPS: dict[tuple[str, str], dict] = {}
ACTIVE_SESSIONS: dict[str, dict] = {}


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    role: Literal["admin", "customer"] | None = None


class OTPVerificationRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    role: Literal["admin", "customer"] | None = None
    otp: str = Field(min_length=6, max_length=6)


class RegisterRequest(BaseModel):
    name: str = "Customer Portal"
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


def _otp_key(email: str, role: str | None = None) -> tuple[str, str]:
    normalized_email = email.strip().lower()
    normalized_role = (role or "customer").strip().lower()
    return normalized_email, normalized_role


def _generate_otp() -> str:
    return f"{secrets.randbelow(900_000) + 100_000:06d}"


def _issue_session(user: dict) -> str:
    token = secrets.token_urlsafe(32)
    ACTIVE_SESSIONS[token] = {
        "role": user["role"],
        "expires_at": time.time() + AUTH_SESSION_TTL_SECONDS,
    }
    return token


def require_session(authorization: str | None) -> str:
    scheme, _, token = (authorization or "").partition(" ")
    session = ACTIVE_SESSIONS.get(token) if scheme.lower() == "bearer" else None
    if not session or time.time() > session["expires_at"]:
        ACTIVE_SESSIONS.pop(token, None)
        raise HTTPException(status_code=401, detail="A valid sign-in session is required")
    return session["role"]


def require_admin(authorization: str | None = Header(default=None)) -> str:
    role = require_session(authorization)
    if role != "admin":
        raise HTTPException(status_code=403, detail="Administrator access is required")
    return role


def _send_otp_email(recipient_email: str, otp_code: str) -> bool:
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_username = os.getenv("SMTP_USERNAME")
    smtp_password = os.getenv("SMTP_PASSWORD")
    smtp_from = os.getenv("SMTP_FROM") or smtp_username
    if not smtp_host or not smtp_username or not smtp_password:
        return False

    message = EmailMessage()
    message["Subject"] = "Your Quantum Cyber TDS login OTP"
    message["From"] = smtp_from or "noreply@quantumcyberdefense.local"
    message["To"] = recipient_email
    message.set_content(
        f"Your login OTP is {otp_code}. It is valid for 5 minutes. "
        "Do not share this code with anyone."
    )

    try:
        if smtp_port == 465:
            with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=20) as server:
                server.login(smtp_username, smtp_password)
                server.send_message(message)
        else:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as server:
                server.starttls()
                server.login(smtp_username, smtp_password)
                server.send_message(message)
        return True
    except Exception as exc:  # pragma: no cover - runtime SMTP failures are environment-dependent
        print(f"[OTP_EMAIL] Failed to send email to {recipient_email}: {exc}")
        return False


@router.post("/login")
def login(payload: LoginRequest):
    user = authenticate_user(payload.email, payload.password, payload.role)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    otp_code = _generate_otp()
    PENDING_OTPS[_otp_key(user["email"], user["role"])] = {
        "otp": otp_code,
        "expires_at": time.time() + OTP_TTL_SECONDS,
        "user": user,
    }

    email_sent = _send_otp_email(user["email"], otp_code)
    response = {
        "requires_otp": True,
        "expires_in": OTP_TTL_SECONDS,
        "message": "OTP sent to your email for verification.",
        "user": user,
    }

    if not email_sent:
        response["otp_code"] = otp_code
        response["message"] = "OTP generated in local development mode. Configure SMTP settings to send email."

    return response


@router.post("/verify-login-otp")
def verify_login_otp(payload: OTPVerificationRequest):
    user = authenticate_user(payload.email, payload.password, payload.role)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    key = _otp_key(user["email"], user["role"])
    pending_otp = PENDING_OTPS.get(key)
    if not pending_otp:
        raise HTTPException(status_code=401, detail="OTP was not requested for this account")

    if time.time() > pending_otp["expires_at"]:
        PENDING_OTPS.pop(key, None)
        raise HTTPException(status_code=401, detail="OTP has expired. Please sign in again.")

    if str(payload.otp).strip() != str(pending_otp["otp"]).strip():
        raise HTTPException(status_code=401, detail="Invalid OTP")

    PENDING_OTPS.pop(key, None)
    return {
        "token": _issue_session(user),
        "user": user,
    }


@router.post("/register")
def register(payload: RegisterRequest):
    try:
        user = register_user(payload.email, payload.password, payload.name)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    return {
        "user": user,
    }
