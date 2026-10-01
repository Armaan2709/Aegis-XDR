"""
AegisAI XDR FastAPI Main Application Entrypoint.

Configures application lifecycle listeners, middleware pipeline, exception handlers,
CORS boundaries, rate limiting, and OpenAPI routing tables.
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.core.config import settings
from app.core.logging import setup_logging, get_logger
from app.core.redis import init_redis, close_redis
from app.core.elasticsearch import init_elasticsearch, close_elasticsearch
from app.core.database import engine
from app.core.exceptions import BaseAppException
from app.middleware.request_id import RequestIDMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.schemas.response import ErrorEnvelope, ErrorDetail
from app.api.v1.router import api_v1_router
from app.models.base import Base

logger = get_logger("app")
limiter = Limiter(key_func=get_remote_address, default_limits=[f"{settings.RATE_LIMIT_PER_MINUTE}/minute"])


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan manager handling startup and shutdown hooks."""
    setup_logging()
    logger.info("Initializing AegisAI XDR Enterprise Platform Core Services...")

    # Initialize connection pools
    await init_redis()
    await init_elasticsearch()

    # Create tables automatically in development / sqlite mode
    if settings.DEBUG or settings.DATABASE_URL.startswith("sqlite"):
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database relational schemas verified/created")

    # Seed default development analyst users if needed
    try:
        from app.core.database import AsyncSessionLocal
        from app.domains.users.services import UserService
        async with AsyncSessionLocal() as session:
            service = UserService(session)
            seeded = await service.seed_default_users()
            await session.commit()
            if seeded > 0:
                logger.info("Seeded initial analyst user accounts", count=seeded)
    except Exception as exc:
        logger.warning("User seeding skipped or failed", error=str(exc))

    yield

    # Cleanup resources on shutdown
    logger.info("Shutting down AegisAI XDR Core Services...")
    await close_redis()
    await close_elasticsearch()
    await engine.dispose()
    logger.info("Shutdown sequence complete")


app = FastAPI(
    title=settings.APP_NAME,
    description="An AI-powered autonomous cyber defense platform that thinks, investigates, predicts, and responds to cyber threats in real time.",
    version="0.1.0",
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan,
)

# Attach rate limiter state
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Mount Middleware Pipeline (Order: outer to inner execution)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestIDMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Exception Handlers
@app.exception_handler(BaseAppException)
async def custom_app_exception_handler(request: Request, exc: BaseAppException) -> JSONResponse:
    """Handle custom application domain exceptions into unified ErrorEnvelope format."""
    correlation_id = getattr(request.state, "correlation_id", None)
    logger.warning(
        "Domain exception intercepted",
        code=exc.code,
        message=exc.message,
        status_code=exc.status_code,
    )
    envelope = ErrorEnvelope(
        error=ErrorDetail(code=exc.code, message=exc.message, details=exc.details),
        correlation_id=correlation_id,
    )
    return JSONResponse(status_code=exc.status_code, content=envelope.model_dump(mode="json"))


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Handle Pydantic validation failures into unified ErrorEnvelope format."""
    correlation_id = getattr(request.state, "correlation_id", None)
    logger.warning("Request validation error intercepted", errors=exc.errors())
    envelope = ErrorEnvelope(
        error=ErrorDetail(
            code="VALIDATION_ERROR",
            message="Request body or query validation failed",
            details={"errors": exc.errors()},
        ),
        correlation_id=correlation_id,
    )
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=envelope.model_dump(mode="json"),
    )


@app.exception_handler(Exception)
async def global_unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Sanitize unexpected errors in production to avoid leaking internal stack traces."""
    correlation_id = getattr(request.state, "correlation_id", None)
    logger.error("Unhandled internal server error", error=str(exc), exc_info=True)
    
    # Development mode may expose details, production mode returns generic message
    detail_msg = str(exc) if settings.DEBUG else "An unexpected internal server error occurred."
    
    envelope = ErrorEnvelope(
        error=ErrorDetail(
            code="INTERNAL_SERVER_ERROR",
            message=detail_msg,
            details=None,
        ),
        correlation_id=correlation_id,
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=envelope.model_dump(mode="json"),
    )


# Mount API V1 Central Router
app.include_router(api_v1_router, prefix=settings.API_V1_STR)
