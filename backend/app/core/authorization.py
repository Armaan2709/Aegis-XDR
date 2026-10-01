"""
Enterprise Role-Based Access Control (RBAC) & Authorization Domain.

Provides role definitions, role normalization, privilege hierarchy resolution,
and FastAPI dependency factories for route-level authorization enforcement.
"""

from enum import Enum
from typing import List, Union, Callable
from fastapi import Depends, Request
from app.core.exceptions import PermissionDeniedError
from app.domains.users.router import get_current_user
from app.models.user import User


class RoleEnum(str, Enum):
    """Standardized AegisAI XDR Enterprise SOC Security Roles."""

    ADMIN = "ADMIN"
    SOC_MANAGER = "SOC_MANAGER"
    SENIOR_ANALYST = "SENIOR_ANALYST"
    SOC_ANALYST = "SOC_ANALYST"
    READ_ONLY = "READ_ONLY"


ROLE_HIERARCHY = {
    RoleEnum.ADMIN: 100,
    RoleEnum.SOC_MANAGER: 80,
    RoleEnum.SENIOR_ANALYST: 60,
    RoleEnum.SOC_ANALYST: 40,
    RoleEnum.READ_ONLY: 20,
}


def normalize_role(role_str: str) -> RoleEnum:
    """Normalize arbitrary role string variations into standard RoleEnum."""
    if not role_str:
        return RoleEnum.SOC_ANALYST

    cleaned = role_str.strip().upper().replace(" ", "_")
    if "ADMIN" in cleaned or "COMMANDER" in cleaned:
        return RoleEnum.ADMIN
    elif "MANAGER" in cleaned:
        return RoleEnum.SOC_MANAGER
    elif "SENIOR" in cleaned:
        return RoleEnum.SENIOR_ANALYST
    elif "READ" in cleaned or "OBSERVER" in cleaned:
        return RoleEnum.READ_ONLY
    elif "ANALYST" in cleaned:
        return RoleEnum.SOC_ANALYST

    try:
        return RoleEnum(cleaned)
    except ValueError:
        return RoleEnum.SOC_ANALYST


def require_role(allowed_roles: List[Union[RoleEnum, str]]) -> Callable:
    """FastAPI dependency enforcing that current authenticated user possesses an allowed role."""

    normalized_allowed = [
        r if isinstance(r, RoleEnum) else normalize_role(r) for r in allowed_roles
    ]

    async def role_checker(
        request: Request,
        current_user: User = Depends(get_current_user),
    ) -> User:
        user_role = normalize_role(current_user.role)

        # READ_ONLY restriction: block all mutation HTTP methods regardless of endpoint
        if user_role == RoleEnum.READ_ONLY and request.method not in ("GET", "HEAD", "OPTIONS"):
            raise PermissionDeniedError("READ_ONLY users are not permitted to perform mutating operations")

        # ADMIN override
        if user_role == RoleEnum.ADMIN:
            return current_user

        if user_role not in normalized_allowed:
            raise PermissionDeniedError(
                f"User role '{user_role.value}' is not authorized to access this resource"
            )

        return current_user

    return role_checker
