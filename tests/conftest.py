"""
Global Pytest Configuration and Path Setup for AegisAI XDR.
"""

import sys
from pathlib import Path

# Automatically add backend directory to sys.path for test discovery
backend_dir = Path(__file__).resolve().parent.parent / "backend"
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

import pytest
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from app.models.base import Base


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def async_session():
    """Create in-memory SQLite async database session fixture for isolated testing."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with session_factory() as session:
        yield session

    await engine.dispose()


