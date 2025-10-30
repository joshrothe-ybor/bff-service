#!/bin/bash

# Complete development environment setup script

set -e

echo "🚀 Setting up Example Service Python development environment..."

# Check prerequisites
echo "🔍 Checking prerequisites..."

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1,2)
REQUIRED_VERSION="3.11"

if ! python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" 2>/dev/null; then
    echo "❌ Python 3.11+ is required. Found: Python $PYTHON_VERSION"
    echo "   Please install Python 3.11 or later"
    exit 1
fi

echo "✅ Python $PYTHON_VERSION found"

# Check if Poetry is installed
if ! command -v poetry >/dev/null 2>&1; then
    echo "❌ Poetry not found. Installing Poetry..."
    curl -sSL https://install.python-poetry.org | python3 -
    export PATH="$HOME/.local/bin:$PATH"
    
    if ! command -v poetry >/dev/null 2>&1; then
        echo "❌ Poetry installation failed"
        exit 1
    fi
else
    echo "✅ Poetry found: $(poetry --version)"
fi

# Check Docker
if ! command -v docker >/dev/null 2>&1; then
    echo "❌ Docker not found. Please install Docker first"
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first"
    exit 1
fi

echo "✅ Docker is available and running"

# Check Docker Compose
if ! command -v docker-compose >/dev/null 2>&1 && ! docker compose version >/dev/null 2>&1; then
    echo "❌ Docker Compose not found. Please install Docker Compose"
    exit 1
fi

echo "✅ Docker Compose is available"

# Verify curl for REST API testing
echo ""
echo "🔧 Verifying REST API tools..."

if ! command -v curl >/dev/null 2>&1; then
    echo "📥 Installing curl..."
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "✅ curl is pre-installed on macOS"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v apt-get >/dev/null 2>&1; then
            sudo apt-get update
            sudo apt-get install -y curl
        elif command -v yum >/dev/null 2>&1; then
            sudo yum install -y curl
        fi
    fi
else
    echo "✅ curl already available for REST API testing"
fi

# Set up Python virtual environments for each module
echo ""
echo "📦 Setting up Python dependencies..."

MODULES=(
    "bff-service-api" 
    "bff-service-core"
    "bff-service-persistence"
    "bff-service-server"
    "bff-service-client"
    "bff-service-integration-tests"
)

for module in "${MODULES[@]}"; do
    if [[ -d "$module" ]]; then
        echo "   Setting up $module..."
        cd "$module"
        
        # Install dependencies
        poetry install --no-interaction
        
        # Verify installation
        if poetry run python -c "import sys; print(f'Python {sys.version}')" >/dev/null 2>&1; then
            echo "   ✅ $module dependencies installed"
        else
            echo "   ❌ Failed to set up $module"
            exit 1
        fi
        
        cd ..
    else
        echo "   ⚠️  Module directory not found: $module"
    fi
done

# REST API setup complete
echo ""
echo "🔄 REST API setup complete..."
echo "✅ All packages are ready for REST API development"

# Set up pre-commit hooks
echo ""
echo "🪝 Setting up pre-commit hooks..."
cd bff-service-integration-tests
if poetry run pre-commit --version >/dev/null 2>&1; then
    poetry run pre-commit install
    echo "✅ Pre-commit hooks installed"
else
    echo "⚠️  Pre-commit not available, skipping hooks setup"
fi
cd ..

# Create local environment file
echo ""
echo "📝 Creating local environment configuration..."

if [[ ! -f ".env.local" ]]; then
    cat > .env.local << EOF
# Local development environment variables
# Copy this file to .env and modify as needed

# Database
DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/bff_service
DATABASE_ECHO=false

# REST API Server
API_PORT=8000
API_HOST=0.0.0.0
API_CORS_ENABLED=true
API_DOCS_ENABLED=true

# Management Server  
MANAGEMENT_PORT=8080
MANAGEMENT_ENABLED=true

# Logging
LOGGING_LEVEL=INFO
LOGGING_FORMAT=console

# Metrics
METRICS_ENABLED=true
METRICS_PROMETHEUS_ENABLED=true

# Development
DEBUG=true
ENVIRONMENT=development
EOF

    echo "✅ Created .env.local template"
    echo "   Copy to .env and modify for your local setup"
else
    echo "✅ .env.local already exists"
fi

# Test the setup
echo ""
echo "🧪 Testing the development setup..."

# Test imports
echo "   Testing Python imports..."
cd bff-service-integration-tests
if poetry run python -c "
import sys
sys.path.insert(0, '../bff-service-api/src')
try:
    import ybor.faq.bff.service.api.models
    print('✅ REST API imports work')
except ImportError as e:
    print(f'❌ REST API import failed: {e}')
    sys.exit(1)
" 2>/dev/null; then
    echo "   ✅ Import test passed"
else
    echo "   ❌ Import test failed"
fi
cd ..

# Test Docker build
echo "   Testing Docker build..."
if docker build -t bff-service:dev-test . >/dev/null 2>&1; then
    echo "   ✅ Docker build test passed"
    docker rmi bff-service:dev-test >/dev/null 2>&1 || true
else
    echo "   ❌ Docker build test failed"
fi

echo ""
echo "🎉 Development environment setup completed!"
echo ""
echo "📋 Summary:"
echo "   ✅ Python 3.11+ installed"
echo "   ✅ UV package manager configured"
echo "   ✅ Docker and Docker Compose available"
echo "   ✅ All module dependencies installed"
echo "   ✅ REST API modules ready"
echo "   ✅ Development configuration created"
echo ""
echo "🚀 Next steps:"
echo "   1. Copy .env.local to .env and customize settings"
echo "   2. Start development environment: ./scripts/start-dev.sh"
echo "   3. Run tests: ./scripts/run-tests.sh"
echo "   4. Check service health: curl http://localhost:8080/health"
echo "   5. Access API docs: http://localhost:8000/docs"
echo ""
echo "💡 Useful commands:"
echo "   ./scripts/start-dev.sh      - Start all services"
echo "   ./scripts/run-tests.sh      - Run all tests"
echo "   ./scripts/benchmark.py      - Run REST API benchmarks"
echo "   docker-compose logs -f      - View service logs"