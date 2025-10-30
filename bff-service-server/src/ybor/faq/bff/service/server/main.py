"""
BffService Server Main

This module provides the main entry point for running the BffService
REST API server using Uvicorn.
"""

import asyncio
import logging
import signal
import sys
from typing import Optional

import structlog
import uvicorn
from uvicorn.config import LOGGING_CONFIG

# Import the FastAPI application and settings
from .app import create_app
from .config.settings import get_settings, Settings


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = structlog.get_logger(__name__)


def setup_logging(settings: Settings) -> None:
    """
    Configure structured logging based on settings.
    
    Args:
        settings: Application settings
    """
    log_level = getattr(logging, settings.logging_level.upper(), logging.INFO)
    
    if settings.logging_format.lower() == "json":
        # TODO: Configure structured JSON logging with structlog
        # import structlog
        # structlog.configure(...)
        pass
    
    # Update root logger level
    logging.getLogger().setLevel(log_level)
    
    # Update uvicorn logging
    logging.getLogger("uvicorn").setLevel(log_level)
    logging.getLogger("uvicorn.access").setLevel(log_level)


async def run_server(
    host: str = "0.0.0.0",
    port: int = 8000,
    settings: Optional[Settings] = None,
    reload: bool = False
) -> None:
    """
    Run the FastAPI server with Uvicorn.
    
    Args:
        host: Host to bind the server
        port: Port to bind the server
        settings: Application settings
        reload: Enable auto-reload for development
    """
    if settings is None:
        settings = Settings()
    
    # Setup logging
    setup_logging(settings)
    
    # Create FastAPI application
    app = create_app()
    
    logger.info(f"Starting BffService server on {host}:{port}")
    
    # Configure Uvicorn
    config = uvicorn.Config(
        app=app,
        host=host,
        port=port,
        reload=reload,
        log_level=settings.logging_level.lower(),
        access_log=True,
        use_colors=True,
        loop="asyncio",
        http="httptools",
        ws="websockets",
        lifespan="on",
        timeout_keep_alive=5,
        timeout_graceful_shutdown=30,
    )
    
    # Create and run server
    server = uvicorn.Server(config)
    
    # Handle shutdown gracefully
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        server.should_exit = True
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        await server.serve()
    except Exception as exc:
        logger.error(f"Server error: {exc}")
        raise
    finally:
        logger.info("BffService server stopped")


def main() -> None:
    """
    Main entry point for the server.
    
    This function can be called from command line or used as the target
    for Docker containers.
    """
    # Load settings from environment
    settings = Settings()
    
    logger.info("BffService Server starting...")
    logger.info(f"Debug mode: {settings.debug}")
    logger.info(f"Log level: {settings.logging_level}")
    logger.info(f"Database URL: {settings.database_url.split('@')[-1] if '@' in settings.database_url else 'Not configured'}")
    
    try:
        # Run the server
        asyncio.run(run_server(
            host=settings.api_host,
            port=settings.api_port,
            settings=settings,
            reload=settings.reload
        ))
    except KeyboardInterrupt:
        logger.info("Received interrupt signal, shutting down...")
    except Exception as exc:
        logger.error(f"Failed to start server: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main() 