"""
Integration Tests for AegisAI XDR Observability API Endpoints.
"""

import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

from app.main import app
from app.core.database import get_db
from app.models.base import Base


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def override_get_db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async def _get_db_override():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = _get_db_override
    yield
    app.dependency_overrides.clear()
    await engine.dispose()


@pytest.mark.anyio
async def test_get_observability_overview(override_get_db):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/observability/overview?time_window=24h")
        assert response.status_code == 200
        data = response.json()
        assert "platform" in data
        assert "soc" in data
        assert "pipeline" in data
        assert "agents" in data
        assert "health" in data


@pytest.mark.anyio
async def test_get_observability_sub_endpoints(override_get_db):
    endpoints = [
        "/api/v1/observability/alerts",
        "/api/v1/observability/incidents",
        "/api/v1/observability/pipeline",
        "/api/v1/observability/agents",
        "/api/v1/observability/threat-intelligence",
        "/api/v1/observability/detections",
        "/api/v1/observability/cases",
        "/api/v1/observability/playbooks",
        "/api/v1/observability/system",
    ]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        for ep in endpoints:
            resp = await client.get(ep)
            assert resp.status_code == 200, f"Failed on endpoint {ep}"


@pytest.mark.anyio
async def test_get_prometheus_metrics_exposition(override_get_db):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/observability/metrics")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/plain")
        assert "aegis_alerts_total" in response.text
        assert "aegis_mttd_seconds" in response.text
