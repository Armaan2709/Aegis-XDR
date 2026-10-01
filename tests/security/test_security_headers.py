"""
Security Regression Tests: HTTP Security Headers.

Verifies presence and configuration of enterprise defense-in-depth HTTP headers
(HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
"""

import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.core.database import get_db
from sqlalchemy.ext.asyncio import AsyncSession


@pytest.fixture
async def override_get_db(async_session: AsyncSession):
    async def _get_db_override():
        yield async_session

    app.dependency_overrides[get_db] = _get_db_override
    yield
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_security_headers_present_on_all_responses(override_get_db):
    """Verify that SecurityHeadersMiddleware injects required HTTP security headers."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/health")
        assert response.status_code == 200

        headers = response.headers
        assert headers.get("X-Content-Type-Options") == "nosniff"
        assert headers.get("X-Frame-Options") == "DENY"
        assert headers.get("X-XSS-Protection") == "1; mode=block"
        assert "Strict-Transport-Security" in headers
        assert "max-age=31536000" in headers["Strict-Transport-Security"]
        assert "Content-Security-Policy" in headers
        assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
        assert "Permissions-Policy" in headers
