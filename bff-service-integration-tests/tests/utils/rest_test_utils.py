"""Utilities for REST API testing."""

import asyncio
from typing import AsyncGenerator, Dict, Optional, Any

import httpx
import pytest
from fastapi.testclient import TestClient


class RestTestClient:
    """Test client for REST API testing."""

    def __init__(self, base_url: str = "http://localhost:8000"):
        """Initialize the REST test client.
        
        Args:
            base_url: Base URL for the REST API
        """
        self.base_url = base_url
        self.client: Optional[httpx.AsyncClient] = None
        self.auth_token: Optional[str] = None

    async def __aenter__(self):
        """Async context manager entry."""
        self.client = httpx.AsyncClient(base_url=self.base_url)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.client:
            await self.client.aclose()

    async def authenticate(self, username: str = "test", password: str = "test") -> str:
        """Authenticate and store auth token.
        
        Args:
            username: Username for authentication
            password: Password for authentication
            
        Returns:
            JWT token
        """
        if not self.client:
            raise RuntimeError("Client not initialized. Use within async context manager.")
            
        response = await self.client.post(
            "/auth/login",
            json={"username": username, "password": password}
        )
        
        if response.status_code == 200:
            data = response.json()
            self.auth_token = data.get("access_token")
            return self.auth_token
        else:
            raise RuntimeError(f"Authentication failed: {response.status_code} {response.text}")

    def get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers.
        
        Returns:
            Headers dictionary with Authorization header
        """
        if not self.auth_token:
            return {}
        return {"Authorization": f"Bearer {self.auth_token}"}

    async def get(self, path: str, **kwargs) -> httpx.Response:
        """HTTP GET request."""
        if not self.client:
            raise RuntimeError("Client not initialized. Use within async context manager.")
        return await self.client.get(path, headers=self.get_auth_headers(), **kwargs)

    async def post(self, path: str, **kwargs) -> httpx.Response:
        """HTTP POST request."""
        if not self.client:
            raise RuntimeError("Client not initialized. Use within async context manager.")
        return await self.client.post(path, headers=self.get_auth_headers(), **kwargs)

    async def put(self, path: str, **kwargs) -> httpx.Response:
        """HTTP PUT request."""
        if not self.client:
            raise RuntimeError("Client not initialized. Use within async context manager.")
        return await self.client.put(path, headers=self.get_auth_headers(), **kwargs)

    async def delete(self, path: str, **kwargs) -> httpx.Response:
        """HTTP DELETE request."""
        if not self.client:
            raise RuntimeError("Client not initialized. Use within async context manager.")
        return await self.client.delete(path, headers=self.get_auth_headers(), **kwargs)


class MockApiServer:
    """Mock REST API server for testing."""

    def __init__(self, app, port: int = 0):
        """Initialize the mock server.
        
        Args:
            app: FastAPI application instance
            port: Port to bind to (0 for auto-assigned)
        """
        self.app = app
        self.port = port
        self.test_client: Optional[TestClient] = None

    def start(self) -> TestClient:
        """Start the mock server.
        
        Returns:
            TestClient instance for making requests
        """
        self.test_client = TestClient(self.app)
        return self.test_client

    def stop(self):
        """Stop the mock server."""
        if self.test_client:
            self.test_client.close()
            self.test_client = None


@pytest.fixture
async def rest_client() -> AsyncGenerator[RestTestClient, None]:
    """Pytest fixture for REST test client."""
    async with RestTestClient() as client:
        yield client


@pytest.fixture
def authenticated_rest_client() -> AsyncGenerator[RestTestClient, None]:
    """Pytest fixture for authenticated REST test client."""
    async def _client():
        async with RestTestClient() as client:
            try:
                await client.authenticate()
            except RuntimeError:
                # Authentication might not be implemented yet
                pass
            yield client
    
    return _client()


def assert_response_success(response: httpx.Response, expected_status: int = 200):
    """Assert that a response was successful.
    
    Args:
        response: HTTP response to check
        expected_status: Expected status code
    """
    assert response.status_code == expected_status, (
        f"Expected status {expected_status}, got {response.status_code}. "
        f"Response: {response.text}"
    )


def assert_response_error(response: httpx.Response, expected_status: int):
    """Assert that a response was an error.
    
    Args:
        response: HTTP response to check
        expected_status: Expected error status code
    """
    assert response.status_code == expected_status, (
        f"Expected error status {expected_status}, got {response.status_code}. "
        f"Response: {response.text}"
    )


def assert_json_response(response: httpx.Response, expected_keys: list = None):
    """Assert that response is valid JSON with expected keys.
    
    Args:
        response: HTTP response to check
        expected_keys: List of keys that should be present in JSON response
    """
    assert response.headers.get("content-type", "").startswith("application/json"), (
        "Response is not JSON"
    )
    
    data = response.json()
    assert isinstance(data, dict), "JSON response is not an object"
    
    if expected_keys:
        for key in expected_keys:
            assert key in data, f"Key '{key}' not found in response"


async def wait_for_server(host: str = "localhost", port: int = 8000, timeout: int = 30):
    """Wait for server to be ready.
    
    Args:
        host: Server host
        port: Server port  
        timeout: Maximum wait time in seconds
    """
    start_time = asyncio.get_event_loop().time()
    
    while True:
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(f"http://{host}:{port}/health")
                if response.status_code == 200:
                    return
        except (httpx.ConnectError, httpx.TimeoutException):
            pass
        
        if asyncio.get_event_loop().time() - start_time > timeout:
            raise TimeoutError(f"Server at {host}:{port} not ready within {timeout} seconds")
        
        await asyncio.sleep(1)


def create_test_bff(name: str = "Test Bff", **kwargs) -> Dict[str, Any]:
    """Create test bff data.
    
    Args:
        name: Name for the test bff
        **kwargs: Additional fields
        
    Returns:
        Dictionary with bff data
    """
    data = {
        "name": name,
        "description": f"Test description for {name}",
        "status": "active",
        **kwargs
    }
    return data


def validate_bff_response(response_data: Dict[str, Any], expected_name: str = None):
    """Validate bff response data.
    
    Args:
        response_data: Response data to validate
        expected_name: Expected name value
    """
    required_fields = ["id", "name", "status"]
    for field in required_fields:
        assert field in response_data, f"Field '{field}' missing from response"
    
    if expected_name:
        assert response_data["name"] == expected_name, (
            f"Expected name '{expected_name}', got '{response_data['name']}'"
        ) 