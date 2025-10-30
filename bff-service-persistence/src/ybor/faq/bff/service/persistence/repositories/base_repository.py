"""Base repository class with common CRUD operations."""

import uuid
from typing import Any, Dict, Generic, List, Optional, Type, TypeVar

from sqlalchemy import and_, delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..models.base import Base

T = TypeVar("T", bound=Base)


class BaseRepository(Generic[T]):
    """Base repository class with common CRUD operations."""

    def __init__(self, model: Type[T], session: AsyncSession) -> None:
        """Initialize the repository.
        
        Args:
            model: SQLAlchemy model class
            session: Database session
        """
        self.model = model
        self.session = session

    async def create(self, **kwargs: Any) -> T:
        """Create a new entity.
        
        Args:
            **kwargs: Entity attributes
            
        Returns:
            T: Created entity
        """
        entity = self.model(**kwargs)
        self.session.add(entity)
        await self.session.flush()
        await self.session.refresh(entity)
        return entity

    async def get_by_id(self, id: uuid.UUID) -> Optional[T]:
        """Get entity by ID.
        
        Args:
            id: Entity ID
            
        Returns:
            Optional[T]: Entity if found, None otherwise
        """
        stmt = select(self.model).where(self.model.id == id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_all(
        self, 
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        order_by: Optional[str] = None,
        **filters: Any
    ) -> List[T]:
        """Get all entities with optional filtering and pagination.
        
        Args:
            limit: Maximum number of entities to return
            offset: Number of entities to skip
            order_by: Field to order by
            **filters: Filter conditions
            
        Returns:
            List[T]: List of entities
        """
        stmt = select(self.model)
        
        # Apply filters
        if filters:
            conditions = []
            for key, value in filters.items():
                if hasattr(self.model, key):
                    if isinstance(value, list):
                        conditions.append(getattr(self.model, key).in_(value))
                    else:
                        conditions.append(getattr(self.model, key) == value)
            if conditions:
                stmt = stmt.where(and_(*conditions))
        
        # Apply ordering
        if order_by and hasattr(self.model, order_by):
            stmt = stmt.order_by(getattr(self.model, order_by))
        
        # Apply pagination
        if offset:
            stmt = stmt.offset(offset)
        if limit:
            stmt = stmt.limit(limit)
        
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_by_field(self, field: str, value: Any) -> Optional[T]:
        """Get entity by a specific field.
        
        Args:
            field: Field name
            value: Field value
            
        Returns:
            Optional[T]: Entity if found, None otherwise
        """
        if not hasattr(self.model, field):
            raise ValueError(f"Model {self.model.__name__} does not have field '{field}'")
        
        stmt = select(self.model).where(getattr(self.model, field) == value)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_many_by_field(self, field: str, value: Any) -> List[T]:
        """Get multiple entities by a specific field.
        
        Args:
            field: Field name
            value: Field value
            
        Returns:
            List[T]: List of matching entities
        """
        if not hasattr(self.model, field):
            raise ValueError(f"Model {self.model.__name__} does not have field '{field}'")
        
        stmt = select(self.model).where(getattr(self.model, field) == value)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def update(self, id: uuid.UUID, **kwargs: Any) -> Optional[T]:
        """Update an entity.
        
        Args:
            id: Entity ID
            **kwargs: Fields to update
            
        Returns:
            Optional[T]: Updated entity if found, None otherwise
        """
        # Remove None values
        kwargs = {k: v for k, v in kwargs.items() if v is not None}
        
        if not kwargs:
            return await self.get_by_id(id)
        
        stmt = (
            update(self.model)
            .where(self.model.id == id)
            .values(**kwargs)
            .returning(self.model)
        )
        
        result = await self.session.execute(stmt)
        updated_entity = result.scalar_one_or_none()
        
        if updated_entity:
            await self.session.refresh(updated_entity)
        
        return updated_entity

    async def delete(self, id: uuid.UUID) -> bool:
        """Delete an entity.
        
        Args:
            id: Entity ID
            
        Returns:
            bool: True if entity was deleted, False if not found
        """
        stmt = delete(self.model).where(self.model.id == id)
        result = await self.session.execute(stmt)
        return result.rowcount > 0

    async def exists(self, id: uuid.UUID) -> bool:
        """Check if entity exists.
        
        Args:
            id: Entity ID
            
        Returns:
            bool: True if entity exists, False otherwise
        """
        stmt = select(1).where(self.model.id == id)
        result = await self.session.execute(stmt)
        return result.scalar() is not None

    async def count(self, **filters: Any) -> int:
        """Count entities with optional filtering.
        
        Args:
            **filters: Filter conditions
            
        Returns:
            int: Number of entities
        """
        stmt = select(self.model)
        
        # Apply filters
        if filters:
            conditions = []
            for key, value in filters.items():
                if hasattr(self.model, key):
                    if isinstance(value, list):
                        conditions.append(getattr(self.model, key).in_(value))
                    else:
                        conditions.append(getattr(self.model, key) == value)
            if conditions:
                stmt = stmt.where(and_(*conditions))
        
        # Use func.count for better performance
        from sqlalchemy import func
        stmt = select(func.count()).select_from(stmt.subquery())
        result = await self.session.execute(stmt)
        return result.scalar() or 0

    async def bulk_create(self, entities_data: List[Dict[str, Any]]) -> List[T]:
        """Create multiple entities in bulk.
        
        Args:
            entities_data: List of entity attribute dictionaries
            
        Returns:
            List[T]: List of created entities
        """
        entities = [self.model(**data) for data in entities_data]
        self.session.add_all(entities)
        await self.session.flush()
        
        # Refresh all entities to get generated IDs
        for entity in entities:
            await self.session.refresh(entity)
        
        return entities

    async def bulk_update(self, updates: List[Dict[str, Any]]) -> int:
        """Update multiple entities in bulk.
        
        Args:
            updates: List of update dictionaries, each must contain 'id' field
            
        Returns:
            int: Number of updated entities
        """
        if not updates:
            return 0
        
        total_updated = 0
        for update_data in updates:
            if 'id' not in update_data:
                continue
            
            entity_id = update_data.pop('id')
            stmt = update(self.model).where(self.model.id == entity_id).values(**update_data)
            result = await self.session.execute(stmt)
            total_updated += result.rowcount
        
        return total_updated

    async def bulk_delete(self, ids: List[uuid.UUID]) -> int:
        """Delete multiple entities in bulk.
        
        Args:
            ids: List of entity IDs
            
        Returns:
            int: Number of deleted entities
        """
        if not ids:
            return 0
        
        stmt = delete(self.model).where(self.model.id.in_(ids))
        result = await self.session.execute(stmt)
        return result.rowcount 