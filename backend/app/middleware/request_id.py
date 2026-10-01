"""
Request ID Correlation Middleware.

Generates or propagates unique UUID correlation tokens (`X-Correlation-ID`) across incoming HTTP requests,
enabling end-to-end tracing across application logs and distributed services.
"""

import uuid
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
import structlog


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Middleware attaching unique correlation ID to request state and response headers."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        correlation_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
        request.state.correlation_id = correlation_id

        # Bind correlation ID to structlog context
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(correlation_id=correlation_id)

        response = await call_next(request)
        response.headers["X-Correlation-ID"] = correlation_id
        return response
