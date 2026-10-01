"""
Unit Tests for AegisAI XDR SOCAnalyticsService.
"""

import pytest
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from app.models.base import Base
from app.observability.services import SOCAnalyticsService
from app.observability.schemas import ObservabilityOverview


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def async_session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with session_factory() as session:
        yield session

    await engine.dispose()


@pytest.mark.anyio
async def test_soc_analytics_service_overview(async_session: AsyncSession):
    service = SOCAnalyticsService(async_session)
    overview = await service.get_overview(time_window="24h")

    assert isinstance(overview, ObservabilityOverview)
    assert overview.time_window == "24h"
    assert overview.platform.active_ai_agents == 6
    assert overview.health.overall_status in ("HEALTHY", "DEGRADED")
    assert overview.soc.alert_to_incident_ratio >= 0.0
    assert len(overview.pipeline.stage_performance) == 11
    assert len(overview.agents.agents) == 6
