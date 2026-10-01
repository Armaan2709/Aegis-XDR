"""
AegisAI XDR Elasticsearch Client Manager.

Manages connection health and interfaces to the Elasticsearch telemetry search engine.
"""

import time
from typing import Optional, Dict, Any
from elasticsearch import AsyncElasticsearch
from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger("app")

es_client: Optional[AsyncElasticsearch] = None


async def init_elasticsearch() -> None:
    """Initialize Async Elasticsearch client connection on startup with request timeouts."""
    global es_client
    try:
        kwargs = {
            "request_timeout": 5.0,
            "max_retries": 2,
            "retry_on_timeout": True,
        }
        if settings.ELASTICSEARCH_USERNAME and settings.ELASTICSEARCH_PASSWORD:
            kwargs["basic_auth"] = (
                settings.ELASTICSEARCH_USERNAME,
                settings.ELASTICSEARCH_PASSWORD,
            )

        es_client = AsyncElasticsearch(
            settings.ELASTICSEARCH_URL,
            **kwargs,
        )
        ping_ok = await es_client.ping()
        if ping_ok:
            logger.info("Successfully connected to Elasticsearch telemetry cluster")
        else:
            logger.warning("Elasticsearch ping failed during startup initialization")
    except Exception as exc:
        logger.warning(
            "Elasticsearch connection unavailable during startup",
            error=str(exc),
        )
        es_client = None


async def close_elasticsearch() -> None:
    """Close Elasticsearch client connections on shutdown."""
    global es_client
    if es_client:
        try:
            await es_client.close()
            logger.info("Elasticsearch client connections closed")
        except Exception as exc:
            logger.error("Error closing Elasticsearch client", error=str(exc))
        finally:
            es_client = None


async def check_elasticsearch_health() -> dict:
    """Ping Elasticsearch server to verify operational status with latency measurement."""
    if not es_client:
        return {
            "status": "unhealthy",
            "latency_ms": 0.0,
            "error": "Elasticsearch client not initialized or unavailable",
        }
    start_time = time.monotonic()
    try:
        ping_ok = await es_client.ping()
        latency_ms = round((time.monotonic() - start_time) * 1000, 2)
        if ping_ok:
            return {"status": "healthy", "latency_ms": latency_ms, "error": None}
        else:
            return {
                "status": "unhealthy",
                "latency_ms": latency_ms,
                "error": "Elasticsearch ping returned false",
            }
    except Exception as exc:
        latency_ms = round((time.monotonic() - start_time) * 1000, 2)
        return {
            "status": "unhealthy",
            "latency_ms": latency_ms,
            "error": "Elasticsearch ping exception",
        }

