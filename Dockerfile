# Multi-stage Docker build for Bff Service
FROM python:3.11-slim as builder

# Set environment variables for Python
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

# Set work directory
WORKDIR /app

# Copy all package configurations
COPY pyproject.toml uv.lock* ./
COPY bff-service-core/pyproject.toml ./bff-service-core/
COPY bff-service-persistence/pyproject.toml ./bff-service-persistence/
COPY bff-service-api/pyproject.toml ./bff-service-api/
COPY bff-service-client/pyproject.toml ./bff-service-client/
COPY bff-service-server/pyproject.toml ./bff-service-server/

# Copy all source code
COPY bff-service-core/src ./bff-service-core/src/
COPY bff-service-persistence/src ./bff-service-persistence/src/
COPY bff-service-api/src ./bff-service-api/src/
COPY bff-service-client/src ./bff-service-client/src/
COPY bff-service-server/src ./bff-service-server/src/

# Copy scripts
COPY scripts ./scripts

# Install dependencies
RUN uv sync --frozen --no-dev

# Production stage
FROM python:3.11-slim as production

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/app/.venv/bin:$PATH"

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Set work directory
WORKDIR /app

# Copy virtual environment and full application from builder stage
COPY --from=builder --chown=appuser:appuser /app /app

# Switch to non-root user
USER appuser

# Set working directory to server package to avoid namespace conflicts
WORKDIR /app/bff-service-server/src

# Expose ports (FastAPI default 8000, management 8080)
EXPOSE 8000 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8080/health/live || exit 1

# Default command  
CMD ["python", "-m", "ybor.faq.bff.service.server.main"]