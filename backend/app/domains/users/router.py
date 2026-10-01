"""
Authentication & User Identity API Endpoints Router.

Provides REST endpoints for enterprise user login, registration, and active session identity lookups.
"""

import uuid
from typing import Annotated
from fastapi import APIRouter, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import decode_access_token
from app.core.exceptions import AuthenticationError, NotFoundError
from app.domains.users.schemas import UserCreate, UserRead, Token
from app.domains.users.services import UserService
from app.domains.users.repositories import UserRepository
from app.models.user import User
from app.schemas.response import APIResponse

router = APIRouter(prefix="/auth", tags=["Authentication"])

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User:
    """Dependency injecting authenticated User entity extracted from Bearer JWT."""
    payload = decode_access_token(token)
    user_id_str = payload.get("sub")
    if not user_id_str:
        raise AuthenticationError("Token payload missing subject claim")
    
    try:
        user_id = uuid.UUID(user_id_str)
    except ValueError as exc:
        raise AuthenticationError("Invalid user ID in token") from exc

    repo = UserRepository(db)
    user = await repo.get_by_id(user_id)
    if not user:
        raise NotFoundError("Authenticated user account no longer exists")
    if not user.is_active:
        raise AuthenticationError("User account is inactive")
    return user


@router.post("/register", response_model=APIResponse[UserRead], status_code=status.HTTP_201_CREATED)
async def register(
    user_in: UserCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[UserRead]:
    """Register a new enterprise SOC user account."""
    service = UserService(db)
    user = await service.register_user(user_in)
    return APIResponse(
        message="User account registered successfully",
        data=UserRead.model_validate(user),
    )


@router.post("/login", response_model=APIResponse[Token])
async def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[Token]:
    """Authenticate credentials and issue JWT Bearer Access Token."""
    service = UserService(db)
    user = await service.authenticate_user(form_data.username, form_data.password)
    token = await service.create_user_token(user)
    return APIResponse(
        message="Authentication successful",
        data=token,
    )


@router.get("/me", response_model=APIResponse[UserRead])
async def get_me(
    current_user: Annotated[User, Depends(get_current_user)]
) -> APIResponse[UserRead]:
    """Retrieve current authenticated user profile."""
    return APIResponse(
        message="Current user profile retrieved",
        data=UserRead.model_validate(current_user),
    )
