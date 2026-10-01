"""
Users & Auth Pydantic Validation Schemas.

Defines request/response contracts for user creation, login, JWT token payloads,
and profile responses.
"""

import uuid
from typing import Optional
from pydantic import BaseModel, EmailStr, ConfigDict


class UserBase(BaseModel):
    """Base user properties schema."""

    email: EmailStr
    full_name: Optional[str] = None
    role: str = "SOC Analyst"


class UserCreate(UserBase):
    """User registration request schema."""

    password: str


class UserRead(UserBase):
    """User profile response schema."""

    id: uuid.UUID
    is_active: bool
    is_superuser: bool

    model_config = ConfigDict(from_attributes=True)


class Token(BaseModel):
    """JWT Token response schema."""

    access_token: str
    token_type: str = "bearer"
    expires_in_seconds: int


class TokenData(BaseModel):
    """JWT Claims payload data schema."""

    sub: Optional[str] = None
    user_id: Optional[uuid.UUID] = None
