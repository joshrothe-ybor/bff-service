"""Error codes for centralized business error handling."""

from enum import Enum
from typing import Final


class ErrorCode(Enum):
    """Enumeration of application error codes."""
    
    # Client errors (4xx equivalent)
    INVALID_REQUEST = ("INVALID_REQUEST", "The request contains invalid parameters")
    RESOURCE_NOT_FOUND = ("RESOURCE_NOT_FOUND", "The requested resource was not found")
    RESOURCE_ALREADY_EXISTS = ("RESOURCE_ALREADY_EXISTS", "The resource already exists")
    PERMISSION_DENIED = ("PERMISSION_DENIED", "Permission denied to access this resource")
    AUTHENTICATION_FAILED = ("AUTHENTICATION_FAILED", "Authentication credentials are invalid")
    RATE_LIMIT_EXCEEDED = ("RATE_LIMIT_EXCEEDED", "Rate limit exceeded for this operation")
    PRECONDITION_FAILED = ("PRECONDITION_FAILED", "Precondition for this operation was not met")
    
    # Server errors (5xx equivalent)
    INTERNAL_ERROR = ("INTERNAL_ERROR", "An internal server error occurred")
    SERVICE_UNAVAILABLE = ("SERVICE_UNAVAILABLE", "The service is temporarily unavailable")
    DATABASE_ERROR = ("DATABASE_ERROR", "A database operation failed")
    EXTERNAL_SERVICE_ERROR = ("EXTERNAL_SERVICE_ERROR", "An external service call failed")
    TIMEOUT = ("TIMEOUT", "The operation timed out")
    
    # Validation errors
    VALIDATION_ERROR = ("VALIDATION_ERROR", "Request validation failed")
    CONSTRAINT_VIOLATION = ("CONSTRAINT_VIOLATION", "A constraint was violated")
    
    # Business logic errors
    BUSINESS_RULE_VIOLATION = ("BUSINESS_RULE_VIOLATION", "A business rule was violated")
    OPERATION_NOT_ALLOWED = ("OPERATION_NOT_ALLOWED", "This operation is not allowed in the current state")
    
    # Unimplemented
    NOT_IMPLEMENTED = ("NOT_IMPLEMENTED", "This feature is not yet implemented")

    def __init__(self, error_code: str, default_message: str) -> None:
        self.error_code: Final[str] = error_code
        self.default_message: Final[str] = default_message

    def __str__(self) -> str:
        return self.error_code 