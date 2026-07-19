import os
import hashlib
import hmac
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from fastapi import Request, HTTPException, Cookie
from typing import Optional

SECRET_KEY = os.getenv("SECRET_KEY", "change-this-in-production-please-use-a-long-random-string")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")
SESSION_MAX_AGE = 3600 * 8  # 8 hours

_serializer = URLSafeTimedSerializer(SECRET_KEY)


def create_session_token() -> str:
    return _serializer.dumps({"role": "admin"})


def verify_session_token(token: str) -> bool:
    try:
        _serializer.loads(token, max_age=SESSION_MAX_AGE)
        return True
    except (BadSignature, SignatureExpired):
        return False


def check_password(password: str) -> bool:
    expected = ADMIN_PASSWORD.encode()
    provided = password.encode()
    return hmac.compare_digest(
        hashlib.sha256(expected).digest(),
        hashlib.sha256(provided).digest(),
    )


def require_admin(request: Request):
    token = request.cookies.get("session")
    if not token or not verify_session_token(token):
        raise HTTPException(status_code=302, headers={"Location": "/admin/login"})
    return True
