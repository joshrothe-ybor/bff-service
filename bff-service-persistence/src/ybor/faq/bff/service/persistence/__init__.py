"""Persistence layer with SQLAlchemy async ORM."""

from .database_config import (
    DatabaseConfig,
    get_database_config,
    get_db_session,
    initialize_database,
)
from .entities import BffEntity
from .health import (
    DatabaseHealthCheck,
    get_health_checker,
)
from .models import (
    Base,
    AbstractEntity,
    AbstractCreated,
    AbstractModified,
    AbstractCreatedModified,
    AbstractVersioned,
    AbstractCreatedModifiedVersioned,
    AbstractLookupEntity,
    PageResult,
    PageRequest,
)
from .repositories import (
    BaseRepository,
    BffRepository,
)

__all__ = [
    # Configuration
    "DatabaseConfig",
    "get_database_config",
    "get_db_session",
    "initialize_database",
    # Health checks
    "DatabaseHealthCheck",
    "get_health_checker",
    # Base models
    "Base",
    "AbstractEntity",
    "AbstractCreated",
    "AbstractModified",
    "AbstractCreatedModified",
    "AbstractVersioned",
    "AbstractCreatedModifiedVersioned",
    "AbstractLookupEntity",
    # Pagination
    "PageResult",
    "PageRequest",
    # Entities
    "BffEntity",
    # Repositories
    "BaseRepository",
    "BffRepository",
]