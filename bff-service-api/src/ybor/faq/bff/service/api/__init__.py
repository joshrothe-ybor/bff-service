"""Bff Service API module.

This module provides the business contracts layer including:
- Service interfaces
- Data transfer objects (DTOs)
- Business exceptions
"""

from .bff_service import BffService
from .models import (
    BffDto,
    GetBffRequest,
    GetBffResponse,
    GetBffsRequest,
    GetBffsResponse,
    CreateBffResponse,
    UpdateBffResponse,
    DeleteBffRequest,
    DeleteBffResponse,
)
from .exception.error_code import ErrorCode
from .exception.service_exception import ServiceException

__all__ = [
    # Service interface
    "BffService",
    
    # DTOs
    "BffDto",
    "GetBffRequest",
    "GetBffResponse", 
    "GetBffsRequest",
    "GetBffsResponse",
    "CreateBffResponse",
    "UpdateBffResponse",
    "DeleteBffRequest",
    "DeleteBffResponse",
    
    # Exceptions
    "ErrorCode",
    "ServiceException",
] 