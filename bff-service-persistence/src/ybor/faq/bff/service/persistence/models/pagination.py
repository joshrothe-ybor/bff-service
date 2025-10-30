"""Pagination models and utilities."""

from typing import Generic, List, TypeVar

from pydantic import BaseModel, Field

T = TypeVar('T')


class PageResult(BaseModel, Generic[T]):
    """Generic pagination result container."""
    
    items: List[T] = Field(default_factory=list, description="Items on this page")
    total_elements: int = Field(0, description="Total number of elements across all pages")
    total_pages: int = Field(0, description="Total number of pages")
    current_page: int = Field(0, description="Current page number (0-based)")
    page_size: int = Field(10, description="Number of items per page")
    has_next: bool = Field(False, description="Whether there is a next page")
    has_previous: bool = Field(False, description="Whether there is a previous page")
    next_page: int = Field(0, description="Next page number")
    previous_page: int = Field(0, description="Previous page number")

    class Config:
        """Pydantic configuration."""
        arbitrary_types_allowed = True

    @classmethod
    def create(
        cls,
        items: List[T],
        total_elements: int,
        page: int,
        size: int
    ) -> "PageResult[T]":
        """Create a PageResult from raw pagination data.
        
        Args:
            items: List of items on this page
            total_elements: Total number of elements
            page: Current page number (0-based)
            size: Page size
            
        Returns:
            Configured PageResult instance
        """
        total_pages = (total_elements + size - 1) // size if total_elements > 0 else 0
        has_next = page < (total_pages - 1)
        has_previous = page > 0
        
        return cls(
            items=items,
            total_elements=total_elements,
            total_pages=total_pages,
            current_page=page,
            page_size=size,
            has_next=has_next,
            has_previous=has_previous,
            next_page=page + 1 if has_next else page,
            previous_page=page - 1 if has_previous else page
        )


class PageRequest(BaseModel):
    """Page request parameters."""
    
    page: int = Field(0, description="Page number (0-based)", ge=0)
    size: int = Field(10, description="Page size", ge=1, le=100)

    @property
    def offset(self) -> int:
        """Calculate the offset for database queries."""
        return self.page * self.size 