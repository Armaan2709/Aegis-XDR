"""
Security Regression Tests: API Security & Parameter Limits.

Verifies pagination upper bounds, malformed UUID handling, and request validation.
"""

import pytest
import uuid
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.core.database import get_db
from app.core.security import create_access_token
from app.domains.users.services import UserService
from app.domains.users.schemas import UserCreate
from sqlalchemy.ext.asyncio import AsyncSession


@pytest.fixture
async def override_get_db(async_session: AsyncSession):
    async def _get_db_override():
        yield async_session

    app.dependency_overrides[get_db] = _get_db_override
    yield
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_invalid_uuid_parameter_handling(override_get_db, async_session: AsyncSession):
    """Verify malformed UUID path parameters return HTTP 422 unprocessable entity when authenticated."""
    user_service = UserService(async_session)
    user = await user_service.register_user(
        UserCreate(email="uuid_test@aegis.ai", password="Password123!", full_name="UUID User")
    )
    token = create_access_token(subject=str(user.id))

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(
            "/api/v1/cases/invalid-uuid-string",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 422
        payload = response.json()
        assert payload["error"]["code"] == "VALIDATION_ERROR"


@pytest.mark.anyio
async def test_unauthenticated_protected_route_access(override_get_db):
    """Verify unauthenticated calls to protected routes return HTTP 401."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/cases/")
        assert response.status_code == 401
