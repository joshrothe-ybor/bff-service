"""Base classes for database entities with common patterns."""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Base class for all database entities."""
    pass


class AbstractEntity(Base):
    """Abstract base entity with common ID field."""
    __abstract__ = True

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
        comment="Unique identifier for the entity"
    )


class AbstractCreated(AbstractEntity):
    """Abstract entity with creation timestamp."""
    __abstract__ = True

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        comment="Timestamp when the entity was created"
    )


class AbstractModified(Base):
    """Abstract mixin for entities with modification timestamp."""
    __abstract__ = True

    updated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        onupdate=func.now(),
        comment="Timestamp when the entity was last updated"
    )


class AbstractCreatedModified(AbstractCreated, AbstractModified):
    """Abstract entity with both creation and modification timestamps."""
    __abstract__ = True


class AbstractVersioned(Base):
    """Abstract mixin for entities with version control (optimistic locking)."""
    __abstract__ = True

    version: Mapped[int] = mapped_column(
        nullable=False,
        default=1,
        comment="Version number for optimistic locking"
    )


class AbstractCreatedModifiedVersioned(AbstractCreatedModified, AbstractVersioned):
    """Abstract entity with timestamps and version control."""
    __abstract__ = True


class AbstractLookupEntity(AbstractCreatedModifiedVersioned):
    """Abstract entity for lookup/reference data."""
    __abstract__ = True

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        unique=True,
        comment="Unique name for the lookup entity"
    )
    
    description: Mapped[Optional[str]] = mapped_column(
        String(1000),
        nullable=True,
        comment="Optional description of the lookup entity"
    )

    def __repr__(self) -> str:
        """String representation of the lookup entity."""
        return f"{self.__class__.__name__}(id='{self.id}', name='{self.name}')"

    def __str__(self) -> str:
        """Human-readable string representation."""
        return f"{self.name}" 