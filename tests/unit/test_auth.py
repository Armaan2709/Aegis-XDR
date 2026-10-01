"""
Unit Tests for Auth & Users Domain.

Verifies User schemas, Token models, and JWT claim serializations.
"""

import uuid
from app.domains.users.schemas import (
    UserCreate,
    UserRead,
    Token,
    TokenData,
)


def test_user_create_schema():
    """Verify UserCreate schema validation."""
    user_in = UserCreate(
        email="analyst@aegis.ai",
        password="SecurePassword123!",
        full_name="Lead Analyst",
        role="Tier 3 SOC Analyst",
    )
    assert user_in.email == "analyst@aegis.ai"
    assert user_in.role == "Tier 3 SOC Analyst"


def test_token_schema():
    """Verify JWT Token schema generation."""
    token = Token(
        access_token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        token_type="bearer",
        expires_in_seconds=3600,
    )
    assert token.token_type == "bearer"
    assert token.expires_in_seconds == 3600


def test_token_data_schema():
    """Verify TokenData claims parsing."""
    user_id = uuid.uuid4()
    claims = TokenData(sub="analyst@aegis.ai", user_id=user_id)
    assert claims.sub == "analyst@aegis.ai"
    assert claims.user_id == user_id
