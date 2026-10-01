"""
AegisAI XDR Observability & Logging Strategy.

Configures structured JSON logging with correlation IDs, separated logging channels
(Application, Security, Audit, AI Engine, Playbook Executions), and standard output formatting.
"""

import logging
import sys
from typing import Any, Dict
import structlog

from app.core.config import settings


def setup_logging() -> None:
    """Initialize structured logging pipeline for AegisAI XDR."""
    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)

    # Standardize Python stdlib log formatters
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
    )

    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]

    if settings.LOG_FORMAT.lower() == "json":
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=True)

    structlog.configure(
        processors=shared_processors + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers = [handler]
    root_logger.setLevel(log_level)

    # Mute noisy third-party loggers
    for logger_name in ["uvicorn.access", "asyncio", "sqlalchemy.engine"]:
        logging.getLogger(logger_name).handlers = [handler]


def get_logger(category: str = "app") -> structlog.stdlib.BoundLogger:
    """
    Retrieve a categorized bound logger.

    Supported categories:
    - 'app': Core backend lifecycle & request logs
    - 'security': Authentication, authorization & token logs
    - 'audit': Administrative changes & security audit trails
    - 'ai': Agent reasoning, prompt traces & LLM outputs
    - 'playbook': Automated SOAR playbook execution traces
    """
    return structlog.get_logger(f"aegis.{category}")
