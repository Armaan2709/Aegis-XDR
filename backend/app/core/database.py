"""
AegisAI XDR Relational Persistence Engine.

Configures SQLAlchemy 2.0 Async Engine, async session factory, connection pool options,
and FastAPI database session dependency generators.
"""

from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger("app")

# Determine driver settings for SQLite in-memory fallback vs asyncpg
is_sqlite = settings.DATABASE_URL.startswith("sqlite")

engine_kwargs = {}
if not is_sqlite:
    engine_kwargs.update(
        {
            "pool_size": 20,
            "max_overflow": 10,
            "pool_pre_ping": True,
            "pool_recycle": 3600,
            "pool_timeout": 30,
        }
    )

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG and not is_sqlite,
    **engine_kwargs,
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency injection yield generator for database sessions."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception as exc:
            await session.rollback()
            logger.error("Database transaction rolled back due to error", error=str(exc))
            raise
        finally:
            await session.close()


async def check_database_health() -> dict:
    """Database connectivity health check with latency measurement."""
    import time
    from sqlalchemy import text

    start_time = time.monotonic()
    try:
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
        latency_ms = round((time.monotonic() - start_time) * 1000, 2)
        return {"status": "healthy", "latency_ms": latency_ms, "error": None}
    except Exception as exc:
        latency_ms = round((time.monotonic() - start_time) * 1000, 2)
        logger.error("PostgreSQL health check failed", error=str(exc))
        return {
            "status": "unhealthy",
            "latency_ms": latency_ms,
            "error": "Database connectivity failed",
        }


async def close_db_connection() -> None:
    """Cleanly dispose of database connection pool engines."""
    try:
        await engine.dispose()
        logger.info("Database connection engine disposed cleanly.")
    except Exception as exc:
        logger.error("Error disposing database connection engine", error=str(exc))

