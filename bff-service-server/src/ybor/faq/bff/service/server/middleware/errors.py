"""
Error Handling Middleware

This module provides centralized error handling with consistent error responses
and proper HTTP status codes.
"""

import logging
from typing import Callable

from fastapi import Request, Response, HTTPException
from fastapi.responses import JSONResponse
from starlette.status import HTTP_500_INTERNAL_SERVER_ERROR


logger = logging.getLogger(__name__)


async def error_handling_middleware(request: Request, call_next: Callable) -> Response:
    """
    Middleware for centralized error handling.
    
    Args:
        request: FastAPI request object
        call_next: Next middleware or route handler
        
    Returns:
        Response object or error response
    """
    try:
        response = await call_next(request)
        return response
    
    except HTTPException as exc:
        # Handle FastAPI HTTP exceptions
        correlation_id = getattr(request.state, 'correlation_id', None)
        
        logger.warning(
            f"HTTP exception: {exc.status_code} - {exc.detail}",
            extra={
                "correlation_id": correlation_id,
                "status_code": exc.status_code,
                "detail": exc.detail,
                "path": request.url.path,
                "method": request.method,
            }
        )
        
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "type": "HTTPException",
                    "code": exc.status_code,
                    "message": exc.detail,
                    "correlation_id": correlation_id,
                    "path": request.url.path,
                    "method": request.method,
                }
            },
            headers=exc.headers
        )
    
    except ValueError as exc:
        # Handle validation errors
        correlation_id = getattr(request.state, 'correlation_id', None)
        
        logger.error(
            f"Validation error: {str(exc)}",
            extra={
                "correlation_id": correlation_id,
                "error": str(exc),
                "path": request.url.path,
                "method": request.method,
            },
            exc_info=True
        )
        
        return JSONResponse(
            status_code=400,
            content={
                "error": {
                    "type": "ValidationError",
                    "code": 400,
                    "message": "Invalid input data",
                    "detail": str(exc),
                    "correlation_id": correlation_id,
                    "path": request.url.path,
                    "method": request.method,
                }
            }
        )
    
    except Exception as exc:
        # Handle unexpected errors
        correlation_id = getattr(request.state, 'correlation_id', None)
        
        logger.error(
            f"Unexpected error: {str(exc)}",
            extra={
                "correlation_id": correlation_id,
                "error": str(exc),
                "error_type": type(exc).__name__,
                "path": request.url.path,
                "method": request.method,
            },
            exc_info=True
        )
        
        return JSONResponse(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": {
                    "type": "InternalServerError",
                    "code": HTTP_500_INTERNAL_SERVER_ERROR,
                    "message": "An unexpected error occurred",
                    "correlation_id": correlation_id,
                    "path": request.url.path,
                    "method": request.method,
                }
            }
        ) 