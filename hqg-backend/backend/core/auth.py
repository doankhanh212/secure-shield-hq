from __future__ import annotations

import os
import secrets
from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt
from passlib.context import CryptContext

# ── Secret key ───────────────────────────────────────────────────────
# Must be set via SECRET_KEY environment variable in production.
# A random fallback is generated per-process so it is NEVER the same
# predictable string — but tokens won't survive restarts without a
# persistent key.  Set SECRET_KEY in .env for production.
_SECRET_KEY_ENV = os.getenv("SECRET_KEY", "")
SECRET_KEY: str = _SECRET_KEY_ENV if _SECRET_KEY_ENV else secrets.token_hex(32)

if not _SECRET_KEY_ENV:
    import logging as _logging
    _logging.getLogger(__name__).warning(
        "SECRET_KEY not set — using ephemeral random key. "
        "All tokens will be invalidated on restart. "
        "Set SECRET_KEY in your .env file for production."
    )

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 8  # 8 hours

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def create_access_token(data: dict, expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(token: str) -> dict | None:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        # Reject tokens without subject claim
        if not payload.get("sub"):
            return None
        return payload
    except JWTError:
        return None


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)
