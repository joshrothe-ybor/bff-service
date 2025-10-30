#!/bin/bash

# Test runner script for Example Service

set -e

echo "🧪 Running Example Service tests..."

# Check if we should run tests in Docker or locally
if [[ "${USE_DOCKER:-}" == "true" ]]; then
    echo "🐳 Running tests in Docker..."
    
    # Build test image
    docker build -f Dockerfile.test -t bff-service-test .
    
    # Run tests
    docker run --rm \
        --network bff-service-network \
        -e DATABASE_URL=postgresql+asyncpg://postgres:postgres@postgres:5432/bff_service_test \
        bff-service-test
else
    echo "💻 Running tests locally..."
    
    # Ensure we're in the project root
    cd "$(dirname "$0")/.."
    
    # Install dependencies if needed
    if [[ ! -f ".uv-installed" ]]; then
        echo "📥 Installing dependencies..."
        uv sync --all-extras
        touch .uv-installed
    fi
    
    # Set test environment variables
    export DATABASE_URL=${DATABASE_URL:-"postgresql+asyncpg://postgres:postgres@localhost:5432/bff_service_test"}
    export LOGGING_LEVEL=DEBUG
    export LOGGING_FORMAT=console

    # Set Python path for module imports
    export PYTHONPATH="bff-service/src:bff-service-integration-tests/src"
    
    # Start test database if needed
    if [[ "${START_DB:-}" == "true" ]]; then
        echo "🗄️ Starting test database..."
        docker run -d \
            --name bff-service-test-db \
            -e POSTGRES_DB=bff_service_test \
            -e POSTGRES_USER=postgres \
            -e POSTGRES_PASSWORD=postgres \
            -p 5433:5432 \
            postgres:15-alpine || true
        
        # Wait for database to be ready
        timeout 30 bash -c 'until pg_isready -h localhost -p 5433 -U postgres; do sleep 1; done'
        
        export DATABASE_URL="postgresql+asyncpg://postgres:postgres@localhost:5433/bff_service_test"
    fi
    
    # Run different test suites based on arguments
    case "${1:-all}" in
        unit)
            echo "🔬 Running unit tests..."
            cd bff-service-integration-tests
            uv run pytest tests/unit/ -v --cov=tests
            ;;
        integration)
            echo "🔧 Running integration tests..."
            cd bff-service-integration-tests
            uv run pytest tests/integration/ -v --cov=tests -m "requires_docker"
            ;;
        all)
            echo "🚀 Running all tests..."
            cd bff-service-integration-tests
            uv run pytest tests/ -v --cov=tests
            ;;
        *)
            echo "❌ Unknown test suite: $1"
            echo "Usage: $0 [unit|integration|all]"
            exit 1
            ;;
    esac
    
    # Cleanup test database if we started it
    if [[ "${START_DB:-}" == "true" ]]; then
        echo "🧹 Cleaning up test database..."
        docker stop bff-service-test-db || true
        docker rm bff-service-test-db || true
    fi
fi

echo "✅ Tests completed!"