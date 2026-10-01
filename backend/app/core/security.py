"""
AegisAI XDR Cryptographic & Security Operations.

Handles password hashing with bcrypt, JWT token issuing, signature validation,
and stateless authentication payload extraction.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Union
from jose import JWTError, jwt
import bcrypt
from app.core.config import settings
from app.core.exceptions import AuthenticationError


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a raw password against its bcrypt hashed hash."""
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8")[:72], hashed_password.encode("utf-8"))
    except Exception:
        return False


def get_password_hash(password: str) -> str:
    """Compute a bcrypt salted hash from a raw password."""
    pwd_bytes = password.encode("utf-8")[:72]
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


def create_access_token(
    subject: Union[str, Any], expires_delta: Optional[timedelta] = None
) -> str:
    """Create a signed JWT access token for a subject (user_id/email)."""
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )

    to_encode: Dict[str, Any] = {
        "exp": expire,
        "sub": str(subject),
        "type": "access",
        "iat": datetime.now(timezone.utc),
    }

    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decode and cryptographically verify a JWT access token."""
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        token_type = payload.get("type")
        if token_type != "access":
            raise AuthenticationError("Invalid token type")
        if not payload.get("sub"):
            raise AuthenticationError("Token payload missing subject claim")
        return payload
    except JWTError as exc:
        raise AuthenticationError("Invalid or expired authentication token") from exc

