"""Data transfer objects for the Example Service API."""

from typing import List, Optional

from pydantic import BaseModel, Field


class ExampleDto(BaseModel):
    """Data transfer object for Example entities."""
    
    id: Optional[str] = Field(None, description="Unique identifier for the example")
    name: str = Field(..., description="Name of the example", min_length=1, max_length=255)

    class Config:
        """Pydantic configuration."""
        json_encoders = {
            # Add any custom encoders here if needed
        }


class GetExampleRequest(BaseModel):
    """Request model for getting a single example."""
    
    id: str = Field(..., description="The ID of the example to retrieve")


class GetExampleResponse(BaseModel):
    """Response model for getting a single example."""
    
    example: ExampleDto = Field(..., description="The requested example")


class GetExamplesRequest(BaseModel):
    """Request model for getting multiple examples with pagination."""
    
    start_page: int = Field(0, description="Starting page number (0-based)", ge=0)
    page_size: int = Field(10, description="Number of items per page", ge=1, le=100)


class GetExamplesResponse(BaseModel):
    """Response model for getting multiple examples with pagination metadata."""
    
    examples: List[ExampleDto] = Field(default_factory=list, description="List of examples")
    has_next: bool = Field(False, description="Whether there is a next page")
    has_previous: bool = Field(False, description="Whether there is a previous page")
    next_page: int = Field(0, description="Next page number")
    previous_page: int = Field(0, description="Previous page number")
    total_pages: int = Field(0, description="Total number of pages")
    total_elements: int = Field(0, description="Total number of elements")


class CreateExampleResponse(BaseModel):
    """Response model for creating an example."""
    
    example: ExampleDto = Field(..., description="The created example")


class UpdateExampleResponse(BaseModel):
    """Response model for updating an example."""
    
    example: ExampleDto = Field(..., description="The updated example")


class DeleteExampleRequest(BaseModel):
    """Request model for deleting an example."""
    
    id: str = Field(..., description="The ID of the example to delete")


class DeleteExampleResponse(BaseModel):
    """Response model for deleting an example."""
    
    message: str = Field(..., description="Confirmation message") 