"""
User Domain Data Access Repository.

Abstracts raw SQLAlchemy database queries for user persistence, lookup, and management.
"""

import uuid
from typing import Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.domains.users.schemas import UserCreate
from app.core.security import get_password_hash


class UserRepository:
    """Repository handling database operations for User entities."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_by_id(self, user_id: uuid.UUID) -> Optional[User]:
        """Fetch user by UUID primary key."""
        result = await self.session.execute(select(User).where(User.id == user_id))
        return result.scalar_one_or_none()

    async def get_by_email(self, email: str) -> Optional[User]:
        """Fetch user by unique email address."""
        result = await self.session.execute(select(User).where(User.email == email))
        return result.scalar_one_or_none()

    async def get_by_identifier(self, identifier: str) -> Optional[User]:
        """Fetch user by email address or username fallback (e.g. analyst1 -> analyst1@aegis.ai)."""
        search_email = identifier if "@" in identifier else f"{identifier}@aegis.ai"
        result = await self.session.execute(
            select(User).where((User.email == identifier) | (User.email == search_email))
        )
        return result.scalar_one_or_none()

    async def create(self, user_in: UserCreate) -> User:
        """Persist new User entity in database."""
        db_user = User(
            email=user_in.email,
            hashed_password=get_password_hash(user_in.password),
            full_name=user_in.full_name,
            role=user_in.role,
        )
        self.session.add(db_user)
        await self.session.flush()
        await self.session.refresh(db_user)
        return db_user
