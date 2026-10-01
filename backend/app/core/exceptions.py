"""
AegisAI XDR Core Exception Hierarchy.

Defines domain-specific business exceptions and exception handlers mapping domain failures
to standardized HTTP API error envelopes.
"""

from typing import Any, Dict, Optional


class BaseAppException(Exception):
    """Base exception class for all AegisAI XDR domain errors."""

    def __init__(
        self,
        message: str,
        code: str = "INTERNAL_SERVER_ERROR",
        status_code: int = 500,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details or {}


class NotFoundError(BaseAppException):
    """Resource not found domain error."""

    def __init__(self, message: str = "Requested resource not found", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            code="NOT_FOUND",
            status_code=404,
            details=details,
        )


class AuthenticationError(BaseAppException):
    """Authentication failed error."""

    def __init__(self, message: str = "Authentication failed", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            code="AUTHENTICATION_FAILED",
            status_code=401,
            details=details,
        )


class PermissionDeniedError(BaseAppException):
    """Authorization permission denied error."""

    def __init__(self, message: str = "Permission denied", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            code="PERMISSION_DENIED",
            status_code=403,
            details=details,
        )


class ValidationError(BaseAppException):
    """Business validation rules failed error."""

    def __init__(self, message: str = "Validation failed", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            code="VALIDATION_ERROR",
            status_code=422,
            details=details,
        )


class ConflictError(BaseAppException):
    """Entity state conflict error (e.g. duplicate key)."""

    def __init__(self, message: str = "Resource state conflict", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            code="CONFLICT_ERROR",
            status_code=409,
            details=details,
        )
