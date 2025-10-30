"""Service interface definition for the Bff Service."""

from abc import ABC, abstractmethod

from .models import (
    CreateBffResponse,
    DeleteBffRequest,
    DeleteBffResponse,
    BffDto,
    GetBffRequest,
    GetBffResponse,
    GetBffsRequest,
    GetBffsResponse,
    UpdateBffResponse,
)


class BffService(ABC):
    """Abstract interface for the Bff Service business logic."""

    @abstractmethod
    async def create_bff(self, bff: BffDto) -> CreateBffResponse:
        """Create a new bff.
        
        Args:
            bff: The bff data to create
            
        Returns:
            Response containing the created bff
            
        Raises:
            ServiceException: If creation fails
        """
        pass

    @abstractmethod
    async def get_bffs(self, request: GetBffsRequest) -> GetBffsResponse:
        """Get a paginated list of bffs.
        
        Args:
            request: Pagination request parameters
            
        Returns:
            Response containing bffs and pagination metadata
            
        Raises:
            ServiceException: If retrieval fails
        """
        pass

    @abstractmethod
    async def get_bff(self, request: GetBffRequest) -> GetBffResponse:
        """Get a single bff by ID.
        
        Args:
            request: Request containing the bff ID
            
        Returns:
            Response containing the requested bff
            
        Raises:
            ServiceException: If bff not found or retrieval fails
        """
        pass

    @abstractmethod
    async def update_bff(self, bff: BffDto) -> UpdateBffResponse:
        """Update an existing bff.
        
        Args:
            bff: The updated bff data
            
        Returns:
            Response containing the updated bff
            
        Raises:
            ServiceException: If bff not found or update fails
        """
        pass

    @abstractmethod
    async def delete_bff(self, request: DeleteBffRequest) -> DeleteBffResponse:
        """Delete a bff by ID.
        
        Args:
            request: Request containing the bff ID to delete
            
        Returns:
            Response with confirmation message
            
        Raises:
            ServiceException: If bff not found or deletion fails
        """
        pass 