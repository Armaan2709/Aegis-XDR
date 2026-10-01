"""
Security Regression Tests: Role-Based Access Control (RBAC).

Verifies role privilege hierarchy, read-only mutation restrictions,
case approval permissions, and playbook execution controls.
"""

import pytest
import uuid
from fastapi import Request
from app.core.authorization import RoleEnum, normalize_role, require_role
from app.core.exceptions import PermissionDeniedError
from app.models.user import User


@pytest.mark.anyio
async def test_role_normalization():
    """Verify role string normalization maps variants correctly."""
    assert normalize_role("SOC Analyst") == RoleEnum.SOC_ANALYST
    assert normalize_role("Admin") == RoleEnum.ADMIN
    assert normalize_role("Administrator") == RoleEnum.ADMIN
    assert normalize_role("SOC Manager") == RoleEnum.SOC_MANAGER
    assert normalize_role("Senior Analyst") == RoleEnum.SENIOR_ANALYST
    assert normalize_role("Read Only") == RoleEnum.READ_ONLY
    assert normalize_role("Observer") == RoleEnum.READ_ONLY


@pytest.mark.anyio
async def test_read_only_user_mutation_blocked():
    """Verify READ_ONLY users are blocked from non-GET requests."""
    user = User(
        id=uuid.uuid4(),
        email="observer@aegis.ai",
        role="READ_ONLY",
        is_active=True,
    )
    checker = require_role([RoleEnum.SOC_ANALYST, RoleEnum.SENIOR_ANALYST, RoleEnum.ADMIN])

    mock_request = type("Request", (), {"method": "POST"})()

    with pytest.raises(PermissionDeniedError, match="READ_ONLY users are not permitted"):
        await checker(request=mock_request, current_user=user)


@pytest.mark.anyio
async def test_soc_analyst_blocked_from_senior_actions():
    """Verify tier-1 SOC_ANALYST is blocked from SENIOR_ANALYST/ADMIN operations."""
    user = User(
        id=uuid.uuid4(),
        email="analyst@aegis.ai",
        role="SOC Analyst",
        is_active=True,
    )
    checker = require_role([RoleEnum.SENIOR_ANALYST, RoleEnum.SOC_MANAGER, RoleEnum.ADMIN])

    mock_request = type("Request", (), {"method": "POST"})()

    with pytest.raises(PermissionDeniedError, match="is not authorized"):
        await checker(request=mock_request, current_user=user)


@pytest.mark.anyio
async def test_authorized_roles_permitted():
    """Verify SENIOR_ANALYST, SOC_MANAGER, and ADMIN pass authorization check."""
    checker = require_role([RoleEnum.SENIOR_ANALYST, RoleEnum.SOC_MANAGER, RoleEnum.ADMIN])
    mock_request = type("Request", (), {"method": "POST"})()

    for role_str in ["Senior Analyst", "SOC Manager", "Admin"]:
        user = User(
            id=uuid.uuid4(),
            email=f"{role_str.lower().replace(' ', '')}@aegis.ai",
            role=role_str,
            is_active=True,
        )
        res = await checker(request=mock_request, current_user=user)
        assert res.id == user.id
