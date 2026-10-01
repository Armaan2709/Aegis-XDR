"""
User & Authentication Domain Business Services.

Orchestrates user creation, credential validation, and JWT token issuance.
"""

from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.users.repositories import UserRepository
from app.domains.users.schemas import UserCreate, UserRead, Token
from app.models.user import User
from app.core.security import verify_password, create_access_token
from app.core.exceptions import AuthenticationError, ConflictError, NotFoundError
from app.core.config import settings


class UserService:
    """Service encapsulating user lifecycle management business logic."""

    def __init__(self, session: AsyncSession):
        self.repo = UserRepository(session)

    async def register_user(self, user_in: UserCreate) -> User:
        """Register a new enterprise user account."""
        existing_user = await self.repo.get_by_email(user_in.email)
        if existing_user:
            raise ConflictError(f"User with email '{user_in.email}' already exists.")
        return await self.repo.create(user_in)

    async def authenticate_user(self, identifier: str, password: str) -> User:
        """Authenticate user credentials (email or username) and return User entity."""
        user = await self.repo.get_by_identifier(identifier)
        if not user or not verify_password(password, user.hashed_password):
            raise AuthenticationError("Invalid email or password.")
        if not user.is_active:
            raise AuthenticationError("User account is inactive.")
        return user

    async def seed_default_users(self) -> int:
        """Seed initial development analyst accounts if accounts do not already exist."""
        default_accounts = [
            {
                "email": "analyst1@aegis.ai",
                "password": "password123",
                "full_name": "Analyst One (Lead)",
                "role": "SOC Analyst",
            },
            {
                "email": "analyst@aegis.ai",
                "password": "AegisSOC2026!",
                "full_name": "Senior SOC Analyst",
                "role": "SOC Analyst",
            },
            {
                "email": "admin@aegis.ai",
                "password": "password123",
                "full_name": "Incident Commander Admin",
                "role": "Incident Commander",
            },
        ]
        seeded_count = 0
        for acc in default_accounts:
            existing = await self.repo.get_by_email(acc["email"])
            if not existing:
                await self.repo.create(
                    UserCreate(
                        email=acc["email"],
                        password=acc["password"],
                        full_name=acc["full_name"],
                        role=acc["role"],
                    )
                )
                seeded_count += 1
        return seeded_count

    async def create_user_token(self, user: User) -> Token:
        """Generate JWT access token for authenticated user."""
        access_token = create_access_token(subject=str(user.id))
        return Token(
            access_token=access_token,
            token_type="bearer",
            expires_in_seconds=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )
