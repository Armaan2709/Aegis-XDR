"""
AegisAI XDR Standardized API Envelope Models.

Ensures all REST API endpoints output unified JSON structures with timestamps,
request correlation IDs, payload generic containers, and detailed error metadata.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Generic, List, Optional, TypeVar
from pydantic import BaseModel, Field

T = TypeVar("T")


class APIResponse(BaseModel, Generic[T]):
    """Standard unified successful API response wrapper."""

    success: bool = True
    message: str = "Operation completed successfully"
    data: Optional[T] = None
    correlation_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ErrorDetail(BaseModel):
    """Detailed error object."""

    code: str
    message: str
    details: Optional[Dict[str, Any]] = Field(default_factory=dict)


class ErrorEnvelope(BaseModel):
    """Standard unified error API response wrapper."""

    success: bool = False
    error: ErrorDetail
    correlation_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class PaginationMeta(BaseModel):
    """Metadata container for paginated list endpoints."""

    page: int
    page_size: int
    total_items: int
    total_pages: int


class PaginatedResponse(BaseModel, Generic[T]):
    """Standard response wrapper for paginated collections."""

    success: bool = True
    data: List[T]
    meta: PaginationMeta
    correlation_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @classmethod
    def create(
        cls,
        items: List[T],
        total: int,
        page: int,
        page_size: int,
        correlation_id: Optional[str] = None,
    ) -> "PaginatedResponse[T]":
        total_pages = (total + page_size - 1) // page_size if page_size > 0 else 0
        return cls(
            success=True,
            data=items,
            meta=PaginationMeta(
                page=page,
                page_size=page_size,
                total_items=total,
                total_pages=total_pages,
            ),
            correlation_id=correlation_id,
        )
