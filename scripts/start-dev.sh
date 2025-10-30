#!/bin/bash

# Development startup script for Example Service

set -e

echo "🚀 Starting Example Service development environment..."

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

# Build and start services
echo "📦 Building and starting services..."
docker-compose up --build -d

# Wait for services to be healthy
echo "⏳ Waiting for services to be healthy..."
timeout 60 bash -c 'until docker-compose ps | grep -q "healthy"; do sleep 2; done'

# Show service status
echo "📊 Service status:"
docker-compose ps

# Show useful URLs
echo ""
echo "🎯 Service endpoints:"
echo "  REST API:         http://localhost:8000"
echo "  API Docs:         http://localhost:8000/docs"
echo "  Management API:   http://localhost:8080"
echo "  Health Check:     http://localhost:8080/health"
echo "  Metrics:          http://localhost:8080/metrics"
echo "  Prometheus:       http://localhost:9090"
echo "  Grafana:          http://localhost:3000 (admin/admin)"
echo "  PostgreSQL:       localhost:5432 (postgres/postgres)"

echo ""
echo "✅ Development environment is ready!"
echo ""
echo "💡 Useful commands:"
echo "  View logs:        docker-compose logs -f bff-service"
echo "  Stop services:    docker-compose down"
echo "  Run tests:        ./scripts/run-tests.sh"
echo "  Clean up:         docker-compose down -v"