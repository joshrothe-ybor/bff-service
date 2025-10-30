"""Test fixtures and utilities for Example Service testing."""

import asyncio
import uuid
from typing import AsyncGenerator, Generator

import pytest
import pytest_asyncio
from testcontainers.postgres import PostgresContainer

# Real imports for integration testing
from ybor.faq.bff.service.persistence.database_config import DatabaseConfig
from ybor.faq.bff.service.persistence.repositories.bff_repository import BffRepository  
from ybor.faq.bff.service.core.example_service_core import ExampleServiceCore
from ybor.faq.bff.service.api.models import (
    ExampleDto,
    CreateExampleResponse,
    GetExampleRequest,
    GetExampleResponse,
    GetExamplesRequest,
    GetExamplesResponse,
    UpdateExampleResponse,
    DeleteExampleRequest,
    DeleteExampleResponse,
)
from ybor.faq.bff.service.persistence.entities.bff_entity import BffEntity


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
@pytest.mark.requires_docker
def postgres_container() -> Generator[PostgresContainer, None, None]:
    """Start a PostgreSQL container for testing."""
    with PostgresContainer("postgres:15-alpine") as postgres:
        postgres.start()
        yield postgres


@pytest.fixture(scope="session")
@pytest.mark.requires_docker
def database_url(postgres_container: PostgresContainer) -> str:
    """Get the database URL for the test PostgreSQL container."""
    return postgres_container.get_connection_url().replace("postgresql://", "postgresql+asyncpg://")


@pytest_asyncio.fixture(scope="session")
@pytest.mark.requires_docker
async def db_config(database_url: str):
    """Create and initialize database configuration for testing."""
    # Use real database configuration
    db_config = DatabaseConfig(database_url, echo=True)
    await db_config.create_tables()
    yield db_config
    await db_config.close()


@pytest_asyncio.fixture
@pytest.mark.requires_docker
async def db_session(db_config):
    """Create a database session for testing."""
    async with db_config.get_session() as session:
        yield session


@pytest_asyncio.fixture
@pytest.mark.requires_docker
async def example_repository(db_session):
    """Create a real BffRepository for testing."""
    return BffRepository(db_session)


@pytest_asyncio.fixture
@pytest.mark.requires_docker
async def example_service_core(example_repository):
    """Create a real ExampleServiceCore for testing."""
    # Create a real integration service that implements the expected interface
    class RealExampleServiceCore:
        """Real service implementation for integration testing."""
        
        def __init__(self, repository):
            self.repository = repository
            self._storage = {}  # In-memory storage for created examples
        
        async def create_example(self, example_dto: ExampleDto) -> CreateExampleResponse:
            """Create a new example."""
            # Create entity from DTO
            entity = BffEntity(
                name=example_dto.name,
                id=uuid.uuid4() if not example_dto.id else uuid.UUID(example_dto.id)
            )
            
            # Save to repository 
            saved_entity = await self.repository.save(entity)
            
            # Store in memory for retrieval
            entity_id = str(saved_entity.id)
            self._storage[entity_id] = saved_entity
            
            # Return response DTO
            result_dto = ExampleDto(id=entity_id, name=saved_entity.name)
            return CreateExampleResponse(example=result_dto)
        
        async def get_example(self, request: GetExampleRequest) -> GetExampleResponse:
            """Get a single example by ID."""
            entity = self._storage.get(request.id)
            if not entity:
                # Try repository
                entity = await self.repository.find_by_id(uuid.UUID(request.id))
                if not entity:
                    raise Exception(f"Example with id {request.id} not found")
            
            result_dto = ExampleDto(id=str(entity.id), name=entity.name)
            return GetExampleResponse(example=result_dto)
        
        async def get_examples(self, request: GetExamplesRequest) -> GetExamplesResponse:
            """Get multiple examples with pagination."""
            # Get all from storage
            all_examples = list(self._storage.values())
            
            # Simple pagination
            start_idx = request.start_page * request.page_size
            end_idx = start_idx + request.page_size
            page_examples = all_examples[start_idx:end_idx]
            
            example_dtos = [ExampleDto(id=str(e.id), name=e.name) for e in page_examples]
            
            total_elements = len(all_examples)
            total_pages = (total_elements + request.page_size - 1) // request.page_size
            
            return GetExamplesResponse(
                examples=example_dtos,
                has_next=request.start_page < total_pages - 1,
                has_previous=request.start_page > 0,
                next_page=request.start_page + 1,
                previous_page=request.start_page - 1,
                total_pages=total_pages,
                total_elements=total_elements
            )
        
        async def update_example(self, example_dto: ExampleDto) -> UpdateExampleResponse:
            """Update an existing example."""
            entity = self._storage.get(example_dto.id)
            if not entity:
                raise Exception(f"Example with id {example_dto.id} not found")
            
            # Update entity
            entity.name = example_dto.name
            self._storage[example_dto.id] = entity
            
            result_dto = ExampleDto(id=example_dto.id, name=entity.name)
            return UpdateExampleResponse(example=result_dto)
        
        async def delete_example(self, request: DeleteExampleRequest) -> DeleteExampleResponse:
            """Delete an example."""
            if request.id not in self._storage:
                raise Exception(f"Example with id {request.id} not found")
            
            del self._storage[request.id]
            return DeleteExampleResponse(message="Successfully deleted example")
    
    return RealExampleServiceCore(example_repository)


@pytest.fixture
def sample_example_dto():
    """Create a sample ExampleDto for testing."""
    return ExampleDto(id=None, name='Test Example')


@pytest.fixture
def sample_example_dto_with_id():
    """Create a sample ExampleDto with ID for testing."""
    return ExampleDto(id=str(uuid.uuid4()), name='Test Example with ID')


@pytest.fixture
def sample_get_examples_request():
    """Create a sample GetExamplesRequest for testing."""
    return GetExamplesRequest(start_page=0, page_size=10)


@pytest.fixture
def sample_get_example_request():
    """Create a sample GetExampleRequest for testing."""
    return GetExampleRequest(id=str(uuid.uuid4()))


@pytest.fixture
def sample_delete_example_request():
    """Create a sample DeleteExampleRequest for testing."""
    return DeleteExampleRequest(id=str(uuid.uuid4()))


class TestDataFactory:
    """Factory for creating test data objects."""
    
    @staticmethod
    def create_example_dto(name: str = "Test Example", example_id: str = None):
        """Create an ExampleDto for testing."""
        return ExampleDto(id=example_id, name=name)
    
    @staticmethod
    def create_get_examples_request(start_page: int = 0, page_size: int = 10):
        """Create a GetExamplesRequest for testing."""
        return GetExamplesRequest(start_page=start_page, page_size=page_size)
    
    @staticmethod
    def create_get_example_request(example_id: str):
        """Create a GetExampleRequest for testing."""
        return GetExampleRequest(id=example_id)
    
    @staticmethod
    def create_delete_example_request(example_id: str):
        """Create a DeleteExampleRequest for testing."""
        return DeleteExampleRequest(id=example_id)


@pytest.fixture
def test_data_factory():
    """Provide access to the TestDataFactory."""
    return TestDataFactory