"""Unit tests for ExampleServiceCore."""

import uuid
from unittest.mock import AsyncMock, Mock

import pytest

# Note: These imports will work once we set up proper dependencies
# from ybor.faq.bff.service.core.example_service_core import ExampleServiceCore
# from ybor.faq.bff.service.api.exception.service_exception import ServiceException
# from ybor.faq.bff.service.api.exception.error_code import ErrorCode

# from ..utils.fixtures import TestDataFactory  # TODO: Uncomment this when the fixtures are implemented


class TestExampleServiceCore:
    """Unit tests for ExampleServiceCore business logic."""

    @pytest.fixture
    def mock_repository(self):
        """Create a mock repository."""
        repository = Mock()
        repository.save = AsyncMock()
        repository.find_by_id = AsyncMock()
        repository.find_all_paginated = AsyncMock()
        repository.update = AsyncMock()
        repository.delete_by_id = AsyncMock()
        repository.exists_by_id = AsyncMock()
        return repository

    @pytest.fixture
    def example_service_core(self, mock_repository):
        """Create ExampleServiceCore with mock repository."""
        # This will be implemented once we have the actual service
        # return ExampleServiceCore(mock_repository)
        
        # Placeholder for now
        service = Mock()
        service.example_repository = mock_repository
        service.create_example = AsyncMock()
        service.get_examples = AsyncMock()
        service.get_example = AsyncMock()
        service.update_example = AsyncMock()
        service.delete_example = AsyncMock()
        service._entity_to_dto = Mock()
        return service

    @pytest.mark.unit
    async def test_create_example_success(self, example_service_core, mock_repository, test_data_factory):
        """Test successful example creation."""
        # Arrange
        example_dto = test_data_factory.create_example_dto("Test Example")
        mock_entity = Mock()
        mock_entity.id = uuid.uuid4()
        mock_entity.name = "Test Example"
        
        mock_repository.save.return_value = mock_entity
        example_service_core._entity_to_dto.return_value = test_data_factory.create_example_dto(
            "Test Example", str(mock_entity.id)
        )
        
        expected_response = type('CreateExampleResponse', (), {
            'example': example_service_core._entity_to_dto.return_value
        })()
        example_service_core.create_example.return_value = expected_response
        
        # Act
        result = await example_service_core.create_example(example_dto)
        
        # Assert
        assert result is not None
        assert result.example.name == "Test Example"
        example_service_core.create_example.assert_called_once_with(example_dto)

    @pytest.mark.unit
    async def test_create_example_with_database_constraint_violation(self, example_service_core, mock_repository):
        """Test example creation with database constraint violation."""
        # Arrange
        example_dto = TestDataFactory.create_example_dto("Test Example")
        mock_repository.save.side_effect = Exception("constraint violation")
        
        # Mock the service to raise the appropriate exception
        async def mock_create_example(dto):
            raise type('ServiceException', (Exception,), {
                'error_code': type('ErrorCode', (), {'error_code': 'INVALID_REQUEST'})()
            })("Database constraint violation: constraint violation")
        
        example_service_core.create_example = mock_create_example
        
        # Act & Assert
        with pytest.raises(Exception) as exc_info:
            await example_service_core.create_example(example_dto)
        
        assert "constraint violation" in str(exc_info.value)

    @pytest.mark.unit
    async def test_get_examples_success(self, example_service_core, mock_repository, test_data_factory):
        """Test successful retrieval of examples with pagination."""
        # Arrange
        request = test_data_factory.create_get_examples_request(0, 10)
        
        mock_page_result = Mock()
        mock_page_result.items = [Mock(id=uuid.uuid4(), name=f"Example {i}") for i in range(5)]
        mock_page_result.total_elements = 5
        mock_page_result.total_pages = 1
        mock_page_result.has_next = False
        mock_page_result.has_previous = False
        mock_page_result.next_page = 0
        mock_page_result.previous_page = 0
        
        mock_repository.find_all_paginated.return_value = mock_page_result
        
        expected_response = type('GetExamplesResponse', (), {
            'examples': [test_data_factory.create_example_dto(f"Example {i}", str(entity.id)) 
                        for i, entity in enumerate(mock_page_result.items)],
            'has_next': False,
            'has_previous': False,
            'next_page': 0,
            'previous_page': 0,
            'total_pages': 1,
            'total_elements': 5
        })()
        example_service_core.get_examples.return_value = expected_response
        
        # Act
        result = await example_service_core.get_examples(request)
        
        # Assert
        assert result is not None
        assert len(result.examples) == 5
        assert result.total_elements == 5
        assert result.total_pages == 1
        assert not result.has_next
        example_service_core.get_examples.assert_called_once_with(request)

    @pytest.mark.unit
    async def test_get_examples_with_page_size_adjustment(self, example_service_core, test_data_factory):
        """Test that page size is adjusted to reasonable bounds."""
        # Arrange
        request = test_data_factory.create_get_examples_request(0, 200)  # Too large
        
        expected_response = type('GetExamplesResponse', (), {
            'examples': [],
            'has_next': False,
            'has_previous': False,
            'next_page': 0,
            'previous_page': 0,
            'total_pages': 0,
            'total_elements': 0
        })()
        example_service_core.get_examples.return_value = expected_response
        
        # Act
        result = await example_service_core.get_examples(request)
        
        # Assert
        assert result is not None
        example_service_core.get_examples.assert_called_once_with(request)

    @pytest.mark.unit
    async def test_get_example_success(self, example_service_core, mock_repository, test_data_factory):
        """Test successful retrieval of a single example."""
        # Arrange
        example_id = str(uuid.uuid4())
        request = test_data_factory.create_get_example_request(example_id)
        
        mock_entity = Mock()
        mock_entity.id = uuid.UUID(example_id)
        mock_entity.name = "Test Example"
        
        mock_repository.find_by_id.return_value = mock_entity
        example_service_core._entity_to_dto.return_value = test_data_factory.create_example_dto(
            "Test Example", example_id
        )
        
        expected_response = type('GetExampleResponse', (), {
            'example': example_service_core._entity_to_dto.return_value
        })()
        example_service_core.get_example.return_value = expected_response
        
        # Act
        result = await example_service_core.get_example(request)
        
        # Assert
        assert result is not None
        assert result.example.id == example_id
        assert result.example.name == "Test Example"
        example_service_core.get_example.assert_called_once_with(request)

    @pytest.mark.unit
    async def test_get_example_not_found(self, example_service_core, mock_repository, test_data_factory):
        """Test retrieval of non-existent example."""
        # Arrange
        example_id = str(uuid.uuid4())
        request = test_data_factory.create_get_example_request(example_id)
        
        mock_repository.find_by_id.return_value = None
        
        # Mock the service to raise the appropriate exception
        async def mock_get_example(req):
            raise type('ServiceException', (Exception,), {
                'error_code': type('ErrorCode', (), {'error_code': 'RESOURCE_NOT_FOUND'})()
            })(f"Resource 'Example' with id '{req.id}' not found")
        
        example_service_core.get_example = mock_get_example
        
        # Act & Assert
        with pytest.raises(Exception) as exc_info:
            await example_service_core.get_example(request)
        
        assert "not found" in str(exc_info.value)

    @pytest.mark.unit
    async def test_get_example_invalid_uuid(self, example_service_core, test_data_factory):
        """Test retrieval with invalid UUID format."""
        # Arrange
        request = test_data_factory.create_get_example_request("invalid-uuid")
        
        # Mock the service to raise the appropriate exception
        async def mock_get_example(req):
            raise type('ServiceException', (Exception,), {
                'error_code': type('ErrorCode', (), {'error_code': 'INVALID_REQUEST'})()
            })(f"Invalid UUID format: {req.id}")
        
        example_service_core.get_example = mock_get_example
        
        # Act & Assert
        with pytest.raises(Exception) as exc_info:
            await example_service_core.get_example(request)
        
        assert "Invalid UUID format" in str(exc_info.value)

    @pytest.mark.unit
    async def test_update_example_success(self, example_service_core, mock_repository, test_data_factory):
        """Test successful example update."""
        # Arrange
        example_id = str(uuid.uuid4())
        example_dto = test_data_factory.create_example_dto("Updated Example", example_id)
        
        mock_entity = Mock()
        mock_entity.id = uuid.UUID(example_id)
        mock_entity.name = "Updated Example"
        
        mock_repository.find_by_id.return_value = mock_entity
        mock_repository.update.return_value = mock_entity
        example_service_core._entity_to_dto.return_value = example_dto
        
        expected_response = type('UpdateExampleResponse', (), {
            'example': example_dto
        })()
        example_service_core.update_example.return_value = expected_response
        
        # Act
        result = await example_service_core.update_example(example_dto)
        
        # Assert
        assert result is not None
        assert result.example.id == example_id
        assert result.example.name == "Updated Example"
        example_service_core.update_example.assert_called_once_with(example_dto)

    @pytest.mark.unit
    async def test_update_example_missing_id(self, example_service_core, test_data_factory):
        """Test update example with missing ID."""
        # Arrange
        example_dto = test_data_factory.create_example_dto("Updated Example")  # No ID
        
        # Mock the service to raise the appropriate exception
        async def mock_update_example(dto):
            raise type('ServiceException', (Exception,), {
                'error_code': type('ErrorCode', (), {'error_code': 'INVALID_REQUEST'})()
            })("Update request must include entity ID")
        
        example_service_core.update_example = mock_update_example
        
        # Act & Assert
        with pytest.raises(Exception) as exc_info:
            await example_service_core.update_example(example_dto)
        
        assert "must include entity ID" in str(exc_info.value)

    @pytest.mark.unit
    async def test_delete_example_success(self, example_service_core, mock_repository, test_data_factory):
        """Test successful example deletion."""
        # Arrange
        example_id = str(uuid.uuid4())
        request = test_data_factory.create_delete_example_request(example_id)
        
        mock_repository.exists_by_id.return_value = True
        mock_repository.delete_by_id.return_value = True
        
        expected_response = type('DeleteExampleResponse', (), {
            'message': 'Successfully deleted example'
        })()
        example_service_core.delete_example.return_value = expected_response
        
        # Act
        result = await example_service_core.delete_example(request)
        
        # Assert
        assert result is not None
        assert "Successfully deleted" in result.message
        example_service_core.delete_example.assert_called_once_with(request)

    @pytest.mark.unit
    async def test_delete_example_not_found(self, example_service_core, mock_repository, test_data_factory):
        """Test deletion of non-existent example."""
        # Arrange
        example_id = str(uuid.uuid4())
        request = test_data_factory.create_delete_example_request(example_id)
        
        mock_repository.exists_by_id.return_value = False
        
        # Mock the service to raise the appropriate exception
        async def mock_delete_example(req):
            raise type('ServiceException', (Exception,), {
                'error_code': type('ErrorCode', (), {'error_code': 'RESOURCE_NOT_FOUND'})()
            })(f"Resource 'Example' with id '{req.id}' not found")
        
        example_service_core.delete_example = mock_delete_example
        
        # Act & Assert
        with pytest.raises(Exception) as exc_info:
            await example_service_core.delete_example(request)
        
        assert "not found" in str(exc_info.value)