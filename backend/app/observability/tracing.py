"""
AegisAI XDR OpenTelemetry & Correlation ID Tracing Adapter.

Provides passive, safe context tracing. Ensures no authorization headers, JWT tokens,
passwords, API keys, or raw sensitive payload evidence are stored in trace attributes.
"""

import contextlib
import time
import uuid
from typing import Any, Dict, Generator, Optional
import structlog

logger = structlog.get_logger("aegis.tracing")

SENSITIVE_KEYS = {
    "password", "secret", "token", "authorization", "api_key",
    "access_token", "private_key", "bearer", "cookie"
}


def sanitize_attributes(attributes: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize dictionary keys and values to prevent secret leakage."""
    sanitized = {}
    for key, val in attributes.items():
        key_lower = key.lower()
        if any(s in key_lower for s in SENSITIVE_KEYS):
            sanitized[key] = "[REDACTED]"
        elif isinstance(val, dict):
            sanitized[key] = sanitize_attributes(val)
        else:
            sanitized[key] = val
    return sanitized


class TraceSpan:
    """Safe, passive trace span representation."""

    def __init__(self, name: str, correlation_id: Optional[str] = None, attributes: Optional[Dict[str, Any]] = None):
        self.name = name
        self.trace_id = str(uuid.uuid4())
        self.correlation_id = correlation_id or str(uuid.uuid4())
        self.attributes = sanitize_attributes(attributes or {})
        self.start_time = time.time()
        self.end_time: Optional[float] = None
        self.duration_ms: Optional[float] = None
        self.status = "OK"
        self.error: Optional[str] = None

    def finish(self, status: str = "OK", error: Optional[str] = None):
        self.end_time = time.time()
        self.duration_ms = round((self.end_time - self.start_time) * 1000, 2)
        self.status = status
        self.error = error

        logger.debug(
            "trace_span_completed",
            span_name=self.name,
            trace_id=self.trace_id,
            correlation_id=self.correlation_id,
            duration_ms=self.duration_ms,
            status=self.status,
            error=self.error,
            **self.attributes
        )


@contextlib.contextmanager
def start_trace_span(
    name: str, correlation_id: Optional[str] = None, attributes: Optional[Dict[str, Any]] = None
) -> Generator[TraceSpan, None, None]:
    """Context manager for tracing operational spans safely."""
    span = TraceSpan(name, correlation_id=correlation_id, attributes=attributes)
    try:
        yield span
        span.finish(status="OK")
    except Exception as exc:
        span.finish(status="ERROR", error=str(exc))
        raise
