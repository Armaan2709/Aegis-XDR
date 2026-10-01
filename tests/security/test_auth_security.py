"""
Security Regression Tests: Authentication & JWT Hardening.

Verifies signature verification, expiration enforcement, claim validation,
algorithm confusion resistance, and inactive user rejection.
"""

import pytest
import uuid
from datetime import datetime, timedelta, timezone
from jose import jwt
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import create_access_token, decode_access_token
from app.core.exceptions import AuthenticationError
from app.domains.users.services import UserService
from app.domains.users.schemas import UserCreate
from app.models.user import User


@pytest.mark.anyio
async def test_expired_jwt_token_rejected():
    """Verify that expired JWT access tokens raise AuthenticationError."""
    token = create_access_token(
        subject=str(uuid.uuid4()), expires_delta=timedelta(seconds=-10)
    )
    with pytest.raises(AuthenticationError, match="Invalid or expired"):
        decode_access_token(token)


@pytest.mark.anyio
async def test_malformed_jwt_token_rejected():
    """Verify that malformed JWT tokens raise AuthenticationError."""
    with pytest.raises(AuthenticationError):
        decode_access_token("invalid.jwt.payload")


@pytest.mark.anyio
async def test_jwt_algorithm_manipulation_rejected():
    """Verify that tokens signed with unapproved algorithms are rejected."""
    payload = {
        "sub": str(uuid.uuid4()),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
        "type": "access",
    }
    # Sign with HS512 instead of HS256
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS512")
    with pytest.raises(AuthenticationError):
        decode_access_token(token)


@pytest.mark.anyio
async def test_jwt_missing_subject_claim_rejected():
    """Verify that tokens missing the subject ('sub') claim are rejected."""
    payload = {
        "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
        "type": "access",
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    with pytest.raises(AuthenticationError, match="missing subject claim"):
        decode_access_token(token)


@pytest.mark.anyio
async def test_jwt_invalid_type_claim_rejected():
    """Verify that tokens with type != 'access' are rejected."""
    payload = {
        "sub": str(uuid.uuid4()),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
        "type": "refresh",
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    with pytest.raises(AuthenticationError, match="Invalid token type"):
        decode_access_token(token)


@pytest.mark.anyio
async def test_inactive_user_authentication_rejected(async_session: AsyncSession):
    """Verify that inactive user accounts cannot authenticate."""
    service = UserService(async_session)
    user = await service.register_user(
        UserCreate(
            email=f"inactive_{uuid.uuid4().hex[:6]}@aegis.ai",
            password="SecurePassword123!",
            full_name="Inactive User",
        )
    )
    user.is_active = False
    await async_session.commit()

    with pytest.raises(AuthenticationError, match="inactive"):
        await service.authenticate_user(user.email, "SecurePassword123!")
