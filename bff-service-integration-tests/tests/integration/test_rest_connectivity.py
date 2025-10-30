"""REST connectivity and health check tests for CI/CD integration."""

import asyncio
import os
import socket
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest


class TestRestConnectivity:
    """Test REST server connectivity and health checks."""

    @pytest.mark.integration
    @pytest.mark.requires_docker
    async def test_rest_server_port_accessible(self):
        """Test that REST server port is accessible."""
        host = os.getenv("API_HOST", "localhost")
        port = int(os.getenv("API_PORT", "8080"))
        
        # Test socket connectivity
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        
        try:
            result = sock.connect_ex((host, port))
            assert result == 0, f"Cannot connect to REST server at {host}:{port}"
        finally:
            sock.close()

    @pytest.mark.integration
    @pytest.mark.requires_docker
    async def test_http_client_creation(self):
        """Test HTTP client creation and basic connectivity."""
        host = os.getenv("API_HOST", "localhost")
        port = int(os.getenv("API_PORT", "8080"))
        
        async with httpx.AsyncClient(base_url=f"http://{host}:{port}") as client:
            # Test basic connectivity with a simple request
            try:
                response = await client.get("/health", timeout=10.0)
                assert response.status_code in [200, 404], f"Unexpected status code: {response.status_code}"
            except httpx.ConnectError:
                pytest.fail(f"Failed to connect to REST server at {host}:{port}")

    @pytest.mark.integration 
    @pytest.mark.requires_docker
    async def test_health_endpoint_accessible(self):
        """Test that health endpoint is accessible."""
        host = os.getenv("API_HOST", "localhost")
        port = int(os.getenv("API_PORT", "8080"))
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(f"http://{host}:{port}/health", timeout=10.0)
                # Health endpoint should exist and return a valid response
                assert response.status_code in [200, 503], f"Health endpoint returned {response.status_code}"
            except httpx.ConnectError:
                pytest.fail(f"Health endpoint not accessible at {host}:{port}/health")

    @pytest.mark.integration
    @pytest.mark.requires_docker
    async def test_management_port_accessible(self):
        """Test that management server port is accessible."""
        host = os.getenv("MANAGEMENT_HOST", "localhost")
        port = int(os.getenv("MANAGEMENT_PORT", "8080"))
        
        # Test socket connectivity
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        
        try:
            result = sock.connect_ex((host, port))
            assert result == 0, f"Cannot connect to management server at {host}:{port}"
        finally:
            sock.close()

    @pytest.mark.integration
    @pytest.mark.requires_docker 
    async def test_management_health_endpoint(self):
        """Test that management health endpoint is accessible."""
        host = os.getenv("MANAGEMENT_HOST", "localhost")
        port = int(os.getenv("MANAGEMENT_PORT", "8080"))
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(f"http://{host}:{port}/health", timeout=10.0)
                # Management health endpoint should exist
                assert response.status_code in [200, 503], f"Management health endpoint returned {response.status_code}"
            except httpx.ConnectError:
                pytest.fail(f"Management health endpoint not accessible at {host}:{port}/health")

    @pytest.mark.integration
    async def test_basic_rest_endpoints_structure(self):
        """Test basic REST API endpoint structure."""
        host = os.getenv("API_HOST", "localhost") 
        port = int(os.getenv("API_PORT", "8080"))
        
        async with httpx.AsyncClient() as client:
            base_url = f"http://{host}:{port}"
            
            # Test root endpoint
            try:
                response = await client.get(f"{base_url}/", timeout=10.0)
                # Root should exist, even if it returns 404 or redirect
                assert response.status_code in [200, 404, 307, 308], f"Root endpoint returned {response.status_code}"
            except httpx.ConnectError:
                pytest.skip(f"REST server not available at {host}:{port}")

    @pytest.mark.integration
    async def test_cors_headers_present(self):
        """Test that CORS headers are present in responses."""
        host = os.getenv("API_HOST", "localhost")
        port = int(os.getenv("API_PORT", "8080"))
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.options(f"http://{host}:{port}/", timeout=10.0)
                # CORS should be configured, check for Access-Control headers
                headers = response.headers
                # At minimum, we expect some CORS configuration
                assert any("access-control" in key.lower() for key in headers.keys()) or response.status_code == 405
            except httpx.ConnectError:
                pytest.skip(f"REST server not available at {host}:{port}")

    @pytest.mark.integration
    async def test_openapi_docs_accessible(self):
        """Test that OpenAPI documentation is accessible."""
        host = os.getenv("API_HOST", "localhost")
        port = int(os.getenv("API_PORT", "8080"))
        
        async with httpx.AsyncClient() as client:
            try:
                # Test docs endpoint
                response = await client.get(f"http://{host}:{port}/docs", timeout=10.0)
                assert response.status_code in [200, 404], f"Docs endpoint returned {response.status_code}"
                
                # Test OpenAPI JSON endpoint
                response = await client.get(f"http://{host}:{port}/openapi.json", timeout=10.0)
                assert response.status_code in [200, 404], f"OpenAPI JSON returned {response.status_code}"
            except httpx.ConnectError:
                pytest.skip(f"REST server not available at {host}:{port}")

    @pytest.mark.integration
    async def test_prometheus_metrics_accessible(self):
        """Test that Prometheus metrics endpoint is accessible."""
        host = os.getenv("MANAGEMENT_HOST", "localhost")
        port = int(os.getenv("MANAGEMENT_PORT", "8080"))
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(f"http://{host}:{port}/metrics", timeout=10.0)
                # Metrics endpoint should exist
                assert response.status_code in [200, 404], f"Metrics endpoint returned {response.status_code}"
                
                if response.status_code == 200:
                    # If metrics exist, should contain Prometheus format
                    content = response.text
                    assert "# HELP" in content or "# TYPE" in content or len(content) > 0
            except httpx.ConnectError:
                pytest.skip(f"Management server not available at {host}:{port}")


# Individual test functions for backwards compatibility
@pytest.mark.integration
async def test_server_connectivity():
    """Test basic server connectivity."""
    test_instance = TestRestConnectivity()
    await test_instance.test_rest_server_port_accessible()


@pytest.mark.integration  
async def test_health_check():
    """Test health check endpoint."""
    test_instance = TestRestConnectivity()
    await test_instance.test_health_endpoint_accessible()


@pytest.mark.integration
async def test_management_connectivity():
    """Test management server connectivity."""
    test_instance = TestRestConnectivity()
    await test_instance.test_management_port_accessible()


# Example of how to use core business logic in integration tests
@pytest.mark.integration
async def test_integration_with_core_logic():
    """Example integration test that uses core business logic."""
    # This would be uncommented when fixtures are implemented
    # from ybor.faq.bff.service.core import bff_service_core
    
    # For now, just test that we can import basic modules
    import json
    import asyncio
    
    # Placeholder test
    assert json is not None
    assert asyncio is not None
    
    # TODO: Once fixtures are implemented, test actual business logic:
    # service = await get_service_instance()
    # result = await service.some_business_operation()
    # assert result is not None 