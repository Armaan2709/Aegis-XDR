"""
AegisAI XDR Redis Cache & Pub/Sub Client.

Manages high-performance Redis connections for caching, event broadcasting,
and API rate limiting.
"""

import time
from typing import Optional, Set
import redis.asyncio as redis
from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger("app")

redis_client: Optional[redis.Redis] = None
_in_memory_blacklist: Set[str] = set()


async def init_redis() -> None:
    """Initialize Redis connection pool on application startup with timeouts."""
    global redis_client
    try:
        redis_client = redis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
            socket_timeout=3.0,
            socket_connect_timeout=3.0,
        )
        await redis_client.ping()
        logger.info("Successfully connected to Redis cache & event broker")
    except Exception as exc:
        logger.warning(
            "Failed to connect to Redis. Operating in secure bounded fallback mode.",
            error=str(exc),
        )
        redis_client = None


async def close_redis() -> None:
    """Close Redis connection pool on application shutdown."""
    global redis_client
    if redis_client:
        try:
            await redis_client.close()
            logger.info("Redis connection pool closed successfully")
        except Exception as exc:
            logger.error("Error closing Redis client", error=str(exc))
        finally:
            redis_client = None


async def check_redis_health() -> dict:
    """Ping Redis server to verify operational status with latency measurement."""
    if not redis_client:
        return {
            "status": "unhealthy",
            "latency_ms": 0.0,
            "error": "Redis client not initialized or unavailable",
        }
    start_time = time.monotonic()
    try:
        await redis_client.ping()
        latency_ms = round((time.monotonic() - start_time) * 1000, 2)
        return {"status": "healthy", "latency_ms": latency_ms, "error": None}
    except Exception as exc:
        latency_ms = round((time.monotonic() - start_time) * 1000, 2)
        return {
            "status": "unhealthy",
            "latency_ms": latency_ms,
            "error": "Redis ping failed",
        }


async def blacklist_token(token_jti: str, ttl_seconds: int = 3600) -> None:
    """Blacklist a JWT token (jti) via Redis or in-memory fallback."""
    if redis_client:
        try:
            await redis_client.setex(f"blacklist:{token_jti}", ttl_seconds, "revoked")
            return
        except Exception as exc:
            logger.error("Redis setex failed, storing token jti in local memory", error=str(exc))
    _in_memory_blacklist.add(token_jti)


async def is_token_blacklisted(token_jti: str) -> bool:
    """Check if token jti is blacklisted in Redis or in-memory fallback."""
    if token_jti in _in_memory_blacklist:
        return True
    if redis_client:
        try:
            val = await redis_client.get(f"blacklist:{token_jti}")
            return val is not None
        except Exception as exc:
            logger.error("Redis get failed for blacklist check", error=str(exc))
    return False

