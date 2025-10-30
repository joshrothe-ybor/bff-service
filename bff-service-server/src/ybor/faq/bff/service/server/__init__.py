"""
BffService Server Module

This module provides the production server implementation using Uvicorn
with the FastAPI application.
"""

from .main import main, run_server

__all__ = ["main", "run_server"] 