"""Bff repository with specialized operations."""

import uuid
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..entities.bff_entity import BffEntity
from .base_repository import BaseRepository


class BffRepository(BaseRepository[BffEntity]):
    """Repository for BffEntity with specialized operations."""

    def __init__(self, session: AsyncSession) -> None:
        """Initialize the Bff repository.
        
        Args:
            session: Database session
        """
        super().__init__(BffEntity, session)

    async def get_by_name(self, name: str) -> Optional[BffEntity]:
        """Get bff by name.
        
        Args:
            name: Bff name
            
        Returns:
            Optional[BffEntity]: Entity if found, None otherwise
        """
        return await self.get_by_field("name", name)

    async def get_active(
        self, 
        limit: Optional[int] = None,
        offset: Optional[int] = None
    ) -> List[BffEntity]:
        """Get all active bffs.
        
        Args:
            limit: Maximum number of entities to return
            offset: Number of entities to skip
            
        Returns:
            List[BffEntity]: List of active entities
        """
        return await self.get_all(
            status="ACTIVE",
            limit=limit,
            offset=offset,
            order_by="name"
        )

    async def get_by_status(
        self, 
        status: str,
        limit: Optional[int] = None,
        offset: Optional[int] = None
    ) -> List[BffEntity]:
        """Get bffs by status.
        
        Args:
            status: Status to filter by
            limit: Maximum number of entities to return
            offset: Number of entities to skip
            
        Returns:
            List[BffEntity]: List of entities with the specified status
        """
        return await self.get_all(
            status=status,
            limit=limit,
            offset=offset,
            order_by="name"
        )

    async def search_by_name(self, name_pattern: str) -> List[BffEntity]:
        """Search bffs by name pattern.
        
        Args:
            name_pattern: Name pattern to search for (case-insensitive)
            
        Returns:
            List[BffEntity]: List of matching entities
        """
        stmt = (
            select(self.model)
            .where(self.model.name.ilike(f"%{name_pattern}%"))
            .order_by(self.model.name)
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def activate(self, id: uuid.UUID) -> Optional[BffEntity]:
        """Activate a bff.
        
        Args:
            id: Entity ID
            
        Returns:
            Optional[BffEntity]: Updated entity if found, None otherwise
        """
        return await self.update(id, status="ACTIVE")

    async def deactivate(self, id: uuid.UUID) -> Optional[BffEntity]:
        """Deactivate a bff.
        
        Args:
            id: Entity ID
            
        Returns:
            Optional[BffEntity]: Updated entity if found, None otherwise
        """
        return await self.update(id, status="INACTIVE")

    async def archive(self, id: uuid.UUID) -> Optional[BffEntity]:
        """Archive a bff.
        
        Args:
            id: Entity ID
            
        Returns:
            Optional[BffEntity]: Updated entity if found, None otherwise
        """
        return await self.update(id, status="ARCHIVED")

    async def count_by_status(self) -> dict[str, int]:
        """Count bffs by status.
        
        Returns:
            dict[str, int]: Dictionary mapping status to count
        """
        from sqlalchemy import func
        
        stmt = (
            select(self.model.status, func.count(self.model.id))
            .group_by(self.model.status)
        )
        result = await self.session.execute(stmt)
        return {status: count for status, count in result.fetchall()}

    async def get_recently_created(
        self, 
        days: int = 7,
        limit: Optional[int] = None
    ) -> List[BffEntity]:
        """Get recently created bffs.
        
        Args:
            days: Number of days to look back
            limit: Maximum number of entities to return
            
        Returns:
            List[BffEntity]: List of recently created entities
        """
        from datetime import datetime, timedelta
        from sqlalchemy import func
        
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        stmt = (
            select(self.model)
            .where(self.model.created_at >= cutoff_date)
            .order_by(self.model.created_at.desc())
        )
        
        if limit:
            stmt = stmt.limit(limit)
        
        result = await self.session.execute(stmt)
        return list(result.scalars().all()) 