"""
Metrics Middleware

This module provides Prometheus metrics collection for HTTP requests,
response times, and error rates.
"""

import time
from typing import Callable

from fastapi import Request, Response
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST


# Prometheus metrics
http_requests_total = Counter(
    "http_requests_total",
    "Total number of HTTP requests",
    ["method", "endpoint", "status_code"]
)

http_request_duration_seconds = Histogram(
    "http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "endpoint"]
)

http_requests_in_progress = Counter(
    "http_requests_in_progress",
    "Number of HTTP requests currently being processed",
    ["method", "endpoint"]
)


async def metrics_middleware(request: Request, call_next: Callable) -> Response:
    """
    Middleware for collecting Prometheus metrics.
    
    Args:
        request: FastAPI request object
        call_next: Next middleware or route handler
        
    Returns:
        Response object
    """
    # Skip metrics collection for metrics endpoint itself
    if request.url.path == "/metrics":
        return await call_next(request)
    
    # Get method and endpoint
    method = request.method
    endpoint = request.url.path
    
    # Start timer
    start_time = time.time()
    
    # Increment in-progress counter
    http_requests_in_progress.labels(method=method, endpoint=endpoint).inc()
    
    try:
        # Process request
        response = await call_next(request)
        status_code = response.status_code
        
    except Exception as exc:
        # Handle exceptions
        status_code = 500
        raise
    
    finally:
        # Calculate duration
        duration = time.time() - start_time
        
        # Record metrics
        http_requests_total.labels(
            method=method,
            endpoint=endpoint,
            status_code=status_code
        ).inc()
        
        http_request_duration_seconds.labels(
            method=method,
            endpoint=endpoint
        ).observe(duration)
        
        # Decrement in-progress counter
        http_requests_in_progress.labels(method=method, endpoint=endpoint).dec()
    
    return response


def get_metrics() -> Response:
    """
    Get Prometheus metrics in text format.
    
    Returns:
        Response with Prometheus metrics
    """
    metrics_data = generate_latest()
    return Response(
        content=metrics_data,
        media_type=CONTENT_TYPE_LATEST
    ) 