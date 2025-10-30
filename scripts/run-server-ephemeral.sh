#!/bin/bash

# Script to run the server with ephemeral database using TestContainers
# This provides the same functionality as the .NET example's --ephemeral flag

# Set up Python path for all modules
export PYTHONPATH="bff-service-server/src:bff-service-api/src:bff-service-core/src:bff-service-persistence/src"

# Auto-detect Docker socket for cross-platform compatibility
if [ -z "$DOCKER_HOST" ]; then
    # Try to find Docker socket automatically
    if [ -S "$HOME/.rd/docker.sock" ]; then
        # Rancher Desktop
        export DOCKER_HOST="unix://$HOME/.rd/docker.sock"
        echo "🐳 Using Rancher Desktop Docker socket"
    elif [ -S "$HOME/.docker/run/docker.sock" ]; then
        # Docker Desktop macOS
        export DOCKER_HOST="unix://$HOME/.docker/run/docker.sock"
        echo "🐳 Using Docker Desktop macOS socket"
    elif [ -S "/var/run/docker.sock" ]; then
        # Standard Docker
        export DOCKER_HOST="unix:///var/run/docker.sock"
        echo "🐳 Using standard Docker socket"
    fi
fi

# Run the server with ephemeral flag
exec uv run python -m ybor.faq.bff_service.server.main --ephemeral "$@"