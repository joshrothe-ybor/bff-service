"""Base exception classes for application-specific exceptions."""

from typing import Any, Optional

from .error_code import ErrorCode


class ServiceException(Exception):
    """Base exception class for all application-specific exceptions."""

    def __init__(
        self,
        error_code: ErrorCode,
        message: Optional[str] = None,
        cause: Optional[Exception] = None,
        correlation_id: Optional[str] = None,
        context: Optional[Any] = None,
    ) -> None:
        """Initialize a ServiceException.
        
        Args:
            error_code: The error code enum value
            message: Custom error message, defaults to error_code.default_message
            cause: The underlying exception that caused this error
            correlation_id: Correlation ID for tracing
            context: Additional context information
        """
        self.error_code = error_code
        self.correlation_id = correlation_id
        self.context = context
        
        effective_message = message or error_code.default_message
        super().__init__(effective_message)
        
        if cause:
            self.__cause__ = cause

    @classmethod
    def not_found(cls, resource: str, resource_id: str) -> "ServiceException":
        """Create a resource not found exception."""
        message = f"Resource '{resource}' with id '{resource_id}' not found"
        return cls(ErrorCode.RESOURCE_NOT_FOUND, message)

    @classmethod
    def invalid_request(cls, message: str) -> "ServiceException":
        """Create an invalid request exception."""
        return cls(ErrorCode.INVALID_REQUEST, message)

    @classmethod
    def internal_error(cls, message: str, cause: Optional[Exception] = None) -> "ServiceException":
        """Create an internal error exception."""
        return cls(ErrorCode.INTERNAL_ERROR, message, cause)

    @classmethod
    def validation_error(cls, message: str) -> "ServiceException":
        """Create a validation error exception."""
        return cls(ErrorCode.VALIDATION_ERROR, message)

    @classmethod
    def already_exists(cls, resource: str, resource_id: str) -> "ServiceException":
        """Create a resource already exists exception."""
        message = f"Resource '{resource}' with id '{resource_id}' already exists"
        return cls(ErrorCode.RESOURCE_ALREADY_EXISTS, message)

    @classmethod
    def constraint_violation(cls, message: str) -> "ServiceException":
        """Create a constraint violation exception."""
        return cls(ErrorCode.CONSTRAINT_VIOLATION, message)

    def __str__(self) -> str:
        """String representation of the exception."""
        return (
            f"ServiceException(error_code={self.error_code}, "
            f"message='{self.args[0] if self.args else None}', "
            f"correlation_id='{self.correlation_id}', "
            f"context={self.context})"
        ) 