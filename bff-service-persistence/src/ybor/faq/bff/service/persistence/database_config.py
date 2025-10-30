"""Database configuration and connection management."""

import asyncio
import logging
from typing import AsyncGenerator, Optional

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool, QueuePool

from .models.base import Base

logger = logging.getLogger(__name__)


class DatabaseConfig:
    """Database configuration and session management."""

    def __init__(
        self,
        database_url: str,
        echo: bool = False,
        pool_size: int = 10,
        max_overflow: int = 20,
        pool_timeout: int = 30,
        pool_recycle: int = 3600,
        connect_timeout: int = 10,
        max_retries: int = 3,
        retry_delay: float = 1.0,
    ) -> None:
        """Initialize database configuration.
        
        Args:
            database_url: Database connection URL
            echo: Enable SQL query logging
            pool_size: Number of connections to maintain
            max_overflow: Maximum overflow connections
            pool_timeout: Timeout for getting connection
            pool_recycle: Recycle connections after this many seconds
            connect_timeout: Timeout for initial connection
            max_retries: Maximum connection retry attempts
            retry_delay: Delay between retry attempts
        """
        self.database_url = database_url
        self.echo = echo
        self.pool_size = pool_size
        self.max_overflow = max_overflow
        self.pool_timeout = pool_timeout
        self.pool_recycle = pool_recycle
        self.connect_timeout = connect_timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay

        self._engine: Optional[AsyncEngine] = None
        self._session_factory: Optional[async_sessionmaker[AsyncSession]] = None

    @property
    def engine(self) -> AsyncEngine:
        """Get the database engine."""
        if self._engine is None:
            raise RuntimeError("Database engine not initialized. Call initialize() first.")
        return self._engine

    @property
    def session_factory(self) -> async_sessionmaker[AsyncSession]:
        """Get the session factory."""
        if self._session_factory is None:
            raise RuntimeError("Session factory not initialized. Call initialize() first.")
        return self._session_factory

    def _get_pool_class(self) -> type:
        """Get appropriate pool class based on database URL."""
        if "sqlite" in self.database_url:
            # SQLite doesn't support connection pooling
            return NullPool
        return QueuePool

    async def initialize(self) -> None:
        """Initialize the database engine and session factory."""
        logger.info("Initializing database connection...")
        
        pool_class = self._get_pool_class()
        
        # Create engine with appropriate configuration
        engine_kwargs = {
            "echo": self.echo,
            "poolclass": pool_class,
            "connect_args": {"command_timeout": self.connect_timeout},
        }
        
        # Only add pool settings for pooled connections
        if pool_class != NullPool:
            engine_kwargs.update({
                "pool_size": self.pool_size,
                "max_overflow": self.max_overflow,
                "pool_timeout": self.pool_timeout,
                "pool_recycle": self.pool_recycle,
            })
        
        self._engine = create_async_engine(self.database_url, **engine_kwargs)
        
        # Add connection event listeners
        self._setup_connection_events()
        
        # Create session factory
        self._session_factory = async_sessionmaker(
            bind=self._engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

        # Test the connection with retries
        await self._test_connection_with_retries()
        
        logger.info("Database connection initialized successfully")

    def _setup_connection_events(self) -> None:
        """Set up connection event listeners."""
        
        @event.listens_for(self.engine.sync_engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            """Set SQLite pragmas for better performance and reliability."""
            if "sqlite" in self.database_url:
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
                cursor.execute("PRAGMA cache_size=1000")
                cursor.execute("PRAGMA temp_store=MEMORY")
                cursor.close()

        @event.listens_for(self.engine.sync_engine, "checkout")
        def receive_checkout(dbapi_connection, connection_record, connection_proxy):
            """Log connection checkout."""
            logger.debug("Connection checked out from pool")

        @event.listens_for(self.engine.sync_engine, "checkin")
        def receive_checkin(dbapi_connection, connection_record):
            """Log connection checkin."""
            logger.debug("Connection checked in to pool")

    async def _test_connection_with_retries(self) -> None:
        """Test database connection with retry logic."""
        for attempt in range(1, self.max_retries + 1):
            try:
                async with self.engine.begin() as conn:
                    result = await conn.execute(text("SELECT 1"))
                    await result.fetchone()
                logger.info("Database connection test successful")
                return
            except Exception as e:
                logger.warning(
                    f"Database connection attempt {attempt}/{self.max_retries} failed: {e}"
                )
                if attempt == self.max_retries:
                    logger.error("All database connection attempts failed")
                    raise
                await asyncio.sleep(self.retry_delay * attempt)

    async def create_tables(self) -> None:
        """Create all database tables."""
        logger.info("Creating database tables...")
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database tables created successfully")

    async def drop_tables(self) -> None:
        """Drop all database tables."""
        logger.warning("Dropping all database tables...")
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        logger.info("Database tables dropped")

    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get an async database session.
        
        Yields:
            AsyncSession: Database session
        """
        async with self.session_factory() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()

    async def health_check(self) -> bool:
        """Perform a database health check.
        
        Returns:
            bool: True if database is healthy, False otherwise
        """
        try:
            async with self.engine.begin() as conn:
                result = await conn.execute(text("SELECT 1"))
                await result.fetchone()
            return True
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return False

    async def close(self) -> None:
        """Close the database engine."""
        if self._engine:
            logger.info("Closing database connection...")
            await self._engine.dispose()
            self._engine = None
            self._session_factory = None
            logger.info("Database connection closed")


# Global database instance
db_config: Optional[DatabaseConfig] = None


def get_database_config() -> DatabaseConfig:
    """Get the global database configuration instance."""
    if db_config is None:
        raise RuntimeError("Database not initialized. Call initialize_database() first.")
    return db_config


def initialize_database(
    database_url: str,
    echo: bool = False,
    pool_size: int = 10,
    max_overflow: int = 20,
    pool_timeout: int = 30,
    pool_recycle: int = 3600,
    connect_timeout: int = 10,
    max_retries: int = 3,
    retry_delay: float = 1.0,
) -> DatabaseConfig:
    """Initialize the global database configuration.
    
    Args:
        database_url: Database connection URL
        echo: Enable SQL query logging
        pool_size: Number of connections to maintain
        max_overflow: Maximum overflow connections
        pool_timeout: Timeout for getting connection
        pool_recycle: Recycle connections after this many seconds
        connect_timeout: Timeout for initial connection
        max_retries: Maximum connection retry attempts
        retry_delay: Delay between retry attempts
        
    Returns:
        DatabaseConfig: The initialized database configuration
    """
    global db_config
    db_config = DatabaseConfig(
        database_url=database_url,
        echo=echo,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_timeout=pool_timeout,
        pool_recycle=pool_recycle,
        connect_timeout=connect_timeout,
        max_retries=max_retries,
        retry_delay=retry_delay,
    )
    return db_config


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Dependency injection function for FastAPI to get database sessions.
    
    Yields:
        AsyncSession: Database session
    """
    db = get_database_config()
    async for session in db.get_session():
        yield session 