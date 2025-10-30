"""Core business logic implementation for the Example Service."""

import uuid
from typing import Optional

import structlog

# Note: These imports will work once we set up proper dependencies
# from ybor.faq.bff.service.api.service_service import ExampleService
# from ybor.faq.bff.service.api.models import (
#     CreateExampleResponse,
#     DeleteExampleRequest,
#     DeleteExampleResponse,
#     ExampleDto,
#     GetExampleRequest,
#     GetExampleResponse,
#     GetExamplesRequest,
#     GetExamplesResponse,
#     UpdateExampleResponse,
# )
# from ybor.faq.bff.service.api.exception.service_exception import ServiceException
# from ybor.faq.bff.service.persistence.repositories.example_repository import ExampleRepository
# from ybor.faq.bff.service.persistence.entities.example_entity import ExampleEntity

logger = structlog.get_logger(__name__)


class ExampleServiceCore:
    """Core business logic implementation for Example Service operations."""

    def __init__(self, example_repository) -> None:
        """Initialize the service with required dependencies.
        
        Args:
            example_repository: Repository for Example entity persistence
        """
        self.example_repository = example_repository

    async def create_example(self, example) -> "CreateExampleResponse":
        """Create a new example entity.
        
        Args:
            example: The example data to create
            
        Returns:
            Response containing the created example
            
        Raises:
            ServiceException: If creation fails or constraint violations occur
        """
        logger.info("Creating example entity", name=example.name)
        logger.debug("CreateExample request details", 
                    has_id=example.id is not None,
                    name_length=len(example.name))

        start_time = logger.bind().info("Starting create operation")
        
        try:
            # Create new entity - let database generate ID if not provided
            entity_data = {
                "name": example.name
            }
            
            saved_entity = await self.example_repository.save(entity_data)
            duration_ms = logger.bind().info("Create operation completed")
            
            logger.info("Successfully created example entity",
                       entity_id=saved_entity.id,
                       name=saved_entity.name,
                       duration_ms=duration_ms)

            # Convert entity to DTO
            example_dto = self._entity_to_dto(saved_entity)
            
            return CreateExampleResponse(example=example_dto)
            
        except Exception as e:
            duration_ms = logger.bind().error("Create operation failed")
            logger.error("Failed to create example entity",
                        name=example.name,
                        duration_ms=duration_ms,
                        error=str(e),
                        exc_info=True)

            # Check for common database constraint violations
            error_message = str(e).lower()
            if "constraint" in error_message or "unique" in error_message:
                raise ServiceException.invalid_request(f"Database constraint violation: {str(e)}")
            
            raise ServiceException.internal_error("Failed to create example entity", e)

    async def get_examples(self, request) -> "GetExamplesResponse":
        """Get a paginated list of examples.
        
        Args:
            request: Pagination request parameters
            
        Returns:
            Response containing examples and pagination metadata
        """
        # Normalize page size to reasonable bounds
        requested_page_size = request.page_size
        page_size = max(1, min(requested_page_size, 100))
        
        logger.info("Retrieving examples",
                   start_page=request.start_page,
                   requested_page_size=requested_page_size,
                   adjusted_page_size=page_size)

        if page_size != requested_page_size:
            logger.debug("Page size adjusted",
                        requested=requested_page_size,
                        adjusted=page_size)

        start_time = logger.bind().info("Starting get examples operation")
        
        try:
            # Get paginated results from repository
            page_result = await self.example_repository.find_all_paginated(
                page=request.start_page,
                size=page_size
            )
            
            query_duration_ms = logger.bind().info("Database query completed")
            
            # Convert entities to DTOs
            examples = [self._entity_to_dto(entity) for entity in page_result.items]
            
            total_duration_ms = logger.bind().info("Get examples operation completed")
            
            logger.info("Retrieved examples",
                       count=len(examples),
                       total_elements=page_result.total_elements,
                       total_pages=page_result.total_pages,
                       query_duration_ms=query_duration_ms,
                       total_duration_ms=total_duration_ms)

            return GetExamplesResponse(
                examples=examples,
                has_next=page_result.has_next,
                has_previous=page_result.has_previous,
                next_page=page_result.next_page,
                previous_page=page_result.previous_page,
                total_pages=page_result.total_pages,
                total_elements=page_result.total_elements
            )
            
        except Exception as e:
            duration_ms = logger.bind().error("Get examples operation failed")
            logger.error("Failed to retrieve examples",
                        start_page=request.start_page,
                        page_size=page_size,
                        duration_ms=duration_ms,
                        error=str(e),
                        exc_info=True)
            
            raise ServiceException.internal_error("Failed to retrieve examples", e)

    async def get_example(self, request) -> "GetExampleResponse":
        """Get a single example by ID.
        
        Args:
            request: Request containing the example ID
            
        Returns:
            Response containing the requested example
            
        Raises:
            ServiceException: If example not found or retrieval fails
        """
        entity_id = request.id
        logger.info("Retrieving example entity", entity_id=entity_id)

        # Validate UUID format
        try:
            parsed_id = uuid.UUID(entity_id)
        except ValueError as e:
            logger.warning("Invalid UUID format in getExample request",
                          entity_id=entity_id,
                          error=str(e))
            raise ServiceException.invalid_request(f"Invalid UUID format: {entity_id}")

        start_time = logger.bind().info("Starting get example operation")
        
        try:
            entity = await self.example_repository.find_by_id(parsed_id)
            duration_ms = logger.bind().info("Get example operation completed")
            
            if entity:
                logger.info("Successfully retrieved example entity",
                           entity_id=entity.id,
                           name=entity.name,
                           duration_ms=duration_ms)
                
                example_dto = self._entity_to_dto(entity)
                return GetExampleResponse(example=example_dto)
            
            logger.warning("Example entity not found",
                          entity_id=entity_id,
                          duration_ms=duration_ms)
            raise ServiceException.not_found("Example", entity_id)
            
        except ServiceException:
            # Re-raise service exceptions as-is
            raise
        except Exception as e:
            duration_ms = logger.bind().error("Get example operation failed")
            logger.error("Failed to retrieve example entity",
                        entity_id=entity_id,
                        duration_ms=duration_ms,
                        error=str(e),
                        exc_info=True)
            
            raise ServiceException.internal_error("Failed to retrieve example entity", e)

    async def update_example(self, example) -> "UpdateExampleResponse":
        """Update an existing example.
        
        Args:
            example: The updated example data
            
        Returns:
            Response containing the updated example
            
        Raises:
            ServiceException: If example not found or update fails
        """
        if not example.id:
            logger.warning("Update example request missing required ID field")
            raise ServiceException.invalid_request("Update request must include entity ID")

        entity_id = example.id
        new_name = example.name
        logger.info("Updating example entity", entity_id=entity_id, new_name=new_name)

        # Validate UUID format
        try:
            parsed_id = uuid.UUID(entity_id)
        except ValueError as e:
            logger.warning("Invalid UUID format in updateExample request",
                          entity_id=entity_id,
                          error=str(e))
            raise ServiceException.invalid_request(f"Invalid UUID format: {entity_id}")

        start_time = logger.bind().info("Starting update example operation")
        
        try:
            # First check if entity exists
            existing_entity = await self.example_repository.find_by_id(parsed_id)
            
            if not existing_entity:
                duration_ms = logger.bind().warning("Update failed - entity not found")
                logger.warning("Failed to update example entity - entity not found",
                              entity_id=entity_id,
                              duration_ms=duration_ms)
                raise ServiceException.not_found("Example", entity_id)

            old_name = existing_entity.name
            
            # Update the entity
            update_data = {"name": new_name}
            updated_entity = await self.example_repository.update(parsed_id, update_data)
            
            duration_ms = logger.bind().info("Update example operation completed")
            
            logger.info("Successfully updated example entity",
                       entity_id=entity_id,
                       old_name=old_name,
                       new_name=new_name,
                       duration_ms=duration_ms)

            example_dto = self._entity_to_dto(updated_entity)
            return UpdateExampleResponse(example=example_dto)
            
        except ServiceException:
            # Re-raise service exceptions as-is
            raise
        except Exception as e:
            duration_ms = logger.bind().error("Update example operation failed")
            logger.error("Failed to update example entity",
                        entity_id=entity_id,
                        new_name=new_name,
                        duration_ms=duration_ms,
                        error=str(e),
                        exc_info=True)
            
            raise ServiceException.internal_error("Failed to update example entity", e)

    async def delete_example(self, request) -> "DeleteExampleResponse":
        """Delete an example by ID.
        
        Args:
            request: Request containing the example ID to delete
            
        Returns:
            Response with confirmation message
            
        Raises:
            ServiceException: If example not found or deletion fails
        """
        entity_id = request.id
        logger.info("Deleting example entity", entity_id=entity_id)

        # Validate UUID format
        try:
            parsed_id = uuid.UUID(entity_id)
        except ValueError as e:
            logger.warning("Invalid UUID format in deleteExample request",
                          entity_id=entity_id,
                          error=str(e))
            raise ServiceException.invalid_request(f"Invalid UUID format: {entity_id}")

        start_time = logger.bind().info("Starting delete example operation")
        
        try:
            # Check if entity exists before deletion
            exists = await self.example_repository.exists_by_id(parsed_id)
            
            if not exists:
                duration_ms = logger.bind().warning("Delete failed - entity not found")
                logger.warning("Attempted to delete non-existent example entity",
                              entity_id=entity_id,
                              duration_ms=duration_ms)
                raise ServiceException.not_found("Example", entity_id)

            # Perform deletion
            await self.example_repository.delete_by_id(parsed_id)
            
            duration_ms = logger.bind().info("Delete example operation completed")
            logger.info("Successfully deleted example entity",
                       entity_id=entity_id,
                       duration_ms=duration_ms)

            return DeleteExampleResponse(message="Successfully deleted example")
            
        except ServiceException:
            # Re-raise service exceptions as-is
            raise
        except Exception as e:
            duration_ms = logger.bind().error("Delete example operation failed")
            logger.error("Failed to delete example entity",
                        entity_id=entity_id,
                        duration_ms=duration_ms,
                        error=str(e),
                        exc_info=True)
            
            raise ServiceException.internal_error("Failed to delete example entity", e)

    def _entity_to_dto(self, entity) -> "ExampleDto":
        """Convert an entity to a DTO.
        
        Args:
            entity: The entity to convert
            
        Returns:
            The converted DTO
        """
        return ExampleDto(
            id=str(entity.id),
            name=entity.name
        )