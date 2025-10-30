# Bff Service Python

A modular, enterprise-grade Python REST service with FastAPI and modern tooling.

## 🚀 Getting Started

### Prerequisites
- **Python 3.11+**
- **uv** (modern Python package manager)
- **Docker & Docker Compose** (for database and services)

### Quick Setup

```bash
# 1. Install dependencies
uv sync --dev

# 2. Start database
docker-compose up postgres -d

# 3. Run migrations
uv run bff-service-migrate upgrade

# 4. Start the server
uv run bff-service-server
```

**That's it!** The server runs on:
- **REST API**: `http://localhost:8000`
- **Management/Health**: `http://localhost:8080`

### Alternative: Ephemeral Database

For development without Docker Compose, use the built-in ephemeral database:

```bash
# 1. Install dependencies
uv sync --dev

# 2. Start server with ephemeral database (auto-starts TestContainers PostgreSQL)
./scripts/run-server-ephemeral.sh
```

**Requirements**: Docker must be running (Docker Desktop, Rancher Desktop, etc.)

**Connection Information**: When the ephemeral database starts, detailed connection information is logged to help you connect with database tools:

```
================================================================================
🐘 EPHEMERAL POSTGRESQL DATABASE CONNECTION INFO
================================================================================

📋 Connection Details:
   Host:     localhost
   Port:     54321  (randomized port)
   Database: bff_service
   Username: postgres
   Password: postgres

💻 Connect via psql:
   psql -h localhost -p 54321 -U postgres -d bff_service

🔧 DataGrip/Database Tool Settings:
   Type:     PostgreSQL
   Host:     localhost
   Port:     54321
   Database: bff_service
   User:     postgres
   Password: postgres
================================================================================
```

### Quick Test

```bash
# Health check
curl http://localhost:8080/health

# API endpoints
curl http://localhost:8000/
curl http://localhost:8000/api/v1/bffs

# Authentication
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "test", "password": "test"}'
```

## 🏗️ Build System

This project features a **modern build pipeline** with uv:

```bash
# Build all components
uv build

# Development installation
uv sync --dev
```

The build system automatically:
- ✅ Installs dependencies with deterministic resolution
- ✅ Validates project structure
- ✅ Handles multi-package workspace
- ✅ Provides extensible pipeline for future build steps

## 📋 Essential Commands

### Development
```bash
uv sync --dev                          # Install dependencies with dev tools
uv run bff-service-server          # Start server
uv build                               # Build all packages
```

### Database
```bash
uv run bff-service-migrate upgrade  # Run migrations
uv run bff-service-migrate current  # Check migration status
```

### Testing
```bash
uv run pytest                          # All tests
uv run pytest -m unit                  # Unit tests only
uv run pytest -m integration           # Integration tests only
```

### Code Quality
```bash
uv run black . && uv run isort . && uv run flake8  # Format and lint
uv run mypy                            # Type checking
```

## 🏛️ Architecture

Modular design with clear separation of concerns:

```
bff-service-python/
├── bff-service-api/          # Business contracts and DTOs
├── bff-service-core/         # Business logic implementation
├── bff-service-persistence/  # Database entities and repositories
├── bff-service-server/       # FastAPI server and endpoints
├── bff-service-client/       # HTTP client library
└── bff-service-integration-tests/ # End-to-end testing
```

## ✨ Enterprise Features

### Core Capabilities
- **REST-First**: FastAPI with automatic OpenAPI documentation
- **Async/Await**: Full async implementation using asyncio
- **Database**: SQLAlchemy 2.0 with Alembic migrations
- **Testing**: pytest with TestContainers for integration tests

### Observability
- **Structured Logging**: JSON logging with correlation IDs
- **Metrics**: Prometheus with custom business metrics
- **Health Checks**: Kubernetes-ready endpoints (`/health`, `/health/live`, `/health/ready`)
- **OpenAPI**: Interactive documentation at `/docs`

### Enterprise Middleware
- **Authentication**: JWT with role-based authorization
- **Rate Limiting**: Request throttling
- **CORS**: Cross-origin resource sharing
- **Correlation IDs**: Request tracing across services

## 🔧 Configuration

Key environment variables:

```bash
# Database
DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/bff_service

# Server Ports
API_PORT=8000                     # REST API port
MANAGEMENT_PORT=8080              # Health/metrics port

# Authentication
JWT_SECRET_KEY=your-secret-key
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30

# CORS
CORS_ORIGINS=["http://localhost:3000"]

# Logging
LOG_LEVEL=INFO                    # Application log level
ENVIRONMENT=development           # Deployment environment
```

## 🐳 Docker

### Development
```bash
# Start all services (database + monitoring)
docker-compose up -d

# Build and run service
docker build -t bff-service .
docker run -p 8000:8000 -p 8080:8080 bff-service
```

### Production
The Dockerfile uses **multi-stage builds** with uv for fast, secure containers:
- Non-root execution
- Minimal dependencies
- Optimized layer caching

## 📊 Monitoring

### Included Monitoring Stack
```bash
docker-compose up -d  # Includes Prometheus + Grafana
```

- **Grafana**: `http://localhost:3000` (dashboards included)
- **Prometheus**: `http://localhost:9090` (metrics collection)
- **Application Metrics**: `http://localhost:8080/metrics`

### Key Metrics
- HTTP request rates, latencies, error rates
- Database connection pool status
- Custom business metrics
- Health check status

## 🧪 Testing

### Test Categories
- **Unit Tests**: Fast, isolated component testing
- **Integration Tests**: Database and service integration with TestContainers
- **End-to-End Tests**: Complete API workflow testing

### Running Tests
```bash
# All tests
uv run pytest

# Specific categories
uv run pytest -m unit
uv run pytest -m integration

# With coverage
uv run pytest --cov=ybor --cov-report=html
```

## 🔒 Security

- **Container Security**: Non-root execution, minimal base image
- **Database Security**: Parameterized queries, connection pooling
- **Network Security**: Port isolation, secure configuration
- **Authentication**: JWT-based auth with role-based access control

## 📈 Performance

- **Async Architecture**: Full asyncio implementation
- **Connection Pooling**: Configurable database connection management
- **FastAPI Optimizations**: Pydantic validation, automatic serialization
- **Caching**: Redis integration for performance-critical paths

## 🤝 Contributing

### Development Workflow
1. Fork the repository
2. Run `uv sync --dev` to set up environment
3. Make changes with tests
4. Run `uv run pytest` and code quality checks
5. Submit a pull request

### Code Quality Standards
- **Type Hints**: Full type annotation coverage
- **Formatting**: Black and isort for consistent code style
- **Linting**: Comprehensive checks with flake8 and mypy
- **Testing**: Maintain high test coverage

## 📚 More Information

- **API Documentation**: Interactive docs at `http://localhost:8000/docs`
- **Health Endpoints**: Kubernetes-compatible health checks at `/health/*`
- **OpenAPI Spec**: JSON schema at `http://localhost:8000/openapi.json`