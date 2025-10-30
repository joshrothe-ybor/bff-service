"""Global pytest configuration."""

import asyncio
import os
import sys
from pathlib import Path

import pytest


def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "unit: marks tests as unit tests (deselect with '-m \"not unit\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests (deselect with '-m \"not integration\"')"
    )
    config.addinivalue_line(
        "markers", "slow: marks tests as slow running (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "requires_docker: marks tests that require Docker (deselect with '-m \"not requires_docker\"')"
    )





def pytest_runtest_setup(item):
    """Setup function called before each test."""
    # Skip Docker tests if Docker is not available and skip requested
    if "requires_docker" in item.keywords:
        if not _is_docker_available() and item.config.getoption("--skip-docker", default=False):
            pytest.skip("Docker not available and --skip-docker specified")


def pytest_addoption(parser):
    """Add custom command line options."""
    parser.addoption(
        "--skip-docker",
        action="store_true",
        default=False,
        help="Skip tests that require Docker"
    )
    parser.addoption(
        "--integration-only",
        action="store_true",
        default=False,
        help="Run only integration tests"
    )
    parser.addoption(
        "--unit-only",
        action="store_true",
        default=False,
        help="Run only unit tests"
    )


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers automatically."""
    # Handle command line options
    if config.getoption("--integration-only", default=False):
        # Keep only integration tests
        integration_items = [item for item in items if "integration" in str(item.fspath)]
        items[:] = integration_items
    elif config.getoption("--unit-only", default=False):
        # Keep only unit tests  
        unit_items = [item for item in items if "unit" in str(item.fspath)]
        items[:] = unit_items
    
    for item in items:
        # Add unit marker to tests in unit directory
        if "unit" in str(item.fspath):
            item.add_marker(pytest.mark.unit)
        
        # Add integration marker to tests in integration directory
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
        
        # Add requires_docker marker to integration tests
        if "integration" in str(item.fspath) or "requires_docker" in item.keywords:
            item.add_marker(pytest.mark.requires_docker)


def _is_docker_available() -> bool:
    """Check if Docker is available."""
    try:
        import docker
        client = docker.from_env()
        client.ping()
        return True
    except Exception:
        return False


@pytest.fixture(scope="session")
def event_loop_policy():
    """Set the event loop policy for the test session."""
    return asyncio.DefaultEventLoopPolicy()


@pytest.fixture(scope="session")
def event_loop(event_loop_policy):
    """Create an event loop for the test session."""
    loop = event_loop_policy.new_event_loop()
    yield loop
    loop.close()


# Import fixtures from utils module
# from tests.utils.fixtures import *  # noqa: F403, F401, E402 //TODO: Uncomment this when the fixtures are implemented
from tests.utils.rest_test_utils import *  # noqa: F403, F401, E402