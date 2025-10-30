"""Bff entity definition."""

import uuid
from typing import Optional

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..models.base import AbstractCreatedModifiedVersioned


class BffEntity(AbstractCreatedModifiedVersioned):
    """Entity representing a Bff record.
    
    This is an example entity that demonstrates the archetype patterns.
    Developers can modify this entity or create new ones based on their needs.
    """
    
    __tablename__ = "bff"

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        unique=True,
        comment="Name of the bff"
    )
    
    description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Description of the bff"
    )
    
    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="ACTIVE",
        comment="Status of the bff (ACTIVE, INACTIVE, ARCHIVED)"
    )

    def __init__(
        self, 
        name: str, 
        description: Optional[str] = None, 
        status: str = "ACTIVE", 
        id: Optional[uuid.UUID] = None
    ) -> None:
        """Initialize a BffEntity.
        
        Args:
            name: The name of the bff
            description: Optional description
            status: Status (defaults to ACTIVE)
            id: Optional UUID, will be generated if not provided
        """
        if id is not None:
            self.id = id
        self.name = name
        self.description = description
        self.status = status

    def __repr__(self) -> str:
        """String representation of the entity."""
        return f"BffEntity(id='{self.id}', name='{self.name}', status='{self.status}')"

    def __str__(self) -> str:
        """Human-readable string representation."""
        return f"Bff {self.name} ({self.status})"

    def is_active(self) -> bool:
        """Check if the entity is active."""
        return self.status == "ACTIVE"

    def activate(self) -> None:
        """Activate the entity."""
        self.status = "ACTIVE"

    def deactivate(self) -> None:
        """Deactivate the entity."""
        self.status = "INACTIVE"

    def archive(self) -> None:
        """Archive the entity."""
        self.status = "ARCHIVED" 