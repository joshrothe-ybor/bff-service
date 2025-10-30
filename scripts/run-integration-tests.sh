#!/bin/bash
# Run integration tests locally with CI-like environment
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Default values
SKIP_BUILD=false
SKIP_DOCKER=false
TEST_PATTERN=""
VERBOSE=false
CLEANUP=true

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --skip-docker)
            SKIP_DOCKER=true
            shift
            ;;
        -k|--pattern)
            TEST_PATTERN="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        --no-cleanup)
            CLEANUP=false
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --skip-build     Skip building packages"
            echo "  --skip-docker    Skip Docker stack and use existing services"
            echo "  -k, --pattern    Run only tests matching pattern"
            echo "  -v, --verbose    Verbose output"
            echo "  --no-cleanup     Don't cleanup Docker resources"
            echo "  -h, --help       Show this help"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

print_status "Starting integration tests from $PROJECT_ROOT"

# Cleanup function
cleanup() {
    if [[ "$CLEANUP" == "true" ]]; then
        print_status "Cleaning up project resources only..."
        cd "$PROJECT_ROOT"
        # Only clean up THIS project's resources
        docker-compose down --remove-orphans 2>/dev/null || true
        # Remove only this project's volumes (if any)
        docker volume rm $(docker volume ls -q | grep "bff-service") 2>/dev/null || true
        # Remove only this project's network
        docker network rm bff-service-network 2>/dev/null || true
    fi
}

# Set trap for cleanup
trap cleanup EXIT

# Check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        print_error "Docker is required but not installed"
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        print_error "docker-compose is required but not installed"
        exit 1
    fi
    
    # Check UV
    if ! command -v uv &> /dev/null; then
        print_error "UV is required but not installed"
        print_status "Installing UV..."
        curl -LsSf https://astral.sh/uv/install.sh | sh
        export PATH="$HOME/.cargo/bin:$PATH"
    fi
    
    print_success "Prerequisites check passed"
}

# Build packages
build_packages() {
    if [[ "$SKIP_BUILD" == "true" ]]; then
        print_warning "Skipping package build"
        return
    fi
    
    print_status "Building packages..."
    cd "$PROJECT_ROOT"
    
    # Use workspace build - much simpler!
    # Install root workspace first
    print_status "Installing workspace dependencies..."
    uv sync --all-extras
    
    # Install each sub-package with dependencies  
    for package in bff-service-persistence bff-service-api bff-service-core bff-service-client bff-service-server bff-service-integration-tests; do
        print_status "Installing $package dependencies..."
        cd "$package"
        uv sync --all-extras
        cd ..
    done
    
    print_status "REST API packages ready..."
    
    print_success "Package build completed"
}

# Start Docker stack
start_docker_stack() {
    if [[ "$SKIP_DOCKER" == "true" ]]; then
        print_warning "Skipping Docker stack startup"
        return
    fi
    
    print_status "Starting Docker stack..."
    cd "$PROJECT_ROOT"
    
    # Clean up any existing containers for this project only
    docker-compose down 2>/dev/null || true
    
    # Start services
    docker-compose up --build -d
    
    print_status "Waiting for services to be ready..."
    
    # Wait for services to actually respond (not just Docker health check)
    for i in {1..36}; do  # 36 attempts = 3 minutes max
        print_status "Attempt $i/36: Testing service endpoints..."
        
        # Test REST API service health endpoint
        if curl -s -f http://localhost:8080/health >/dev/null 2>&1; then
            print_success "REST API service is responding!"
            # Give it a few more seconds to fully stabilize
            sleep 5
            break
        fi
        
        if [ $i -eq 36 ]; then
            print_error "Services not ready after 3 minutes"
            print_status "Service status:"
            docker-compose ps
            print_status "Service logs:"
            docker logs bff-service 2>&1 | tail -30
            exit 1
        fi
        
        echo "Services not ready yet, waiting 5 seconds..."
        sleep 5
    done
    
    print_success "Docker stack is running and healthy"
}

# Verify services
verify_services() {
    print_status "Final verification of services..."
    
    # Quick final check that services are still responding
    if ! curl -s -f http://localhost:8080/health >/dev/null 2>&1; then
        print_error "REST API service health check failed"
        print_status "Service logs:"
        docker logs bff-service 2>&1 | tail -20
        return 1
    fi
    
    # Quick database check
    if ! docker-compose exec -T postgres pg_isready -U postgres -d bff_service 2>/dev/null; then
        print_error "Database connectivity check failed"
        return 1
    fi
    
    print_success "All service verification checks passed"
}

# Run tests
run_tests() {
    print_status "Running integration tests..."
    cd "$PROJECT_ROOT/bff-service-integration-tests"
    
    # Set environment variables
    export API_SERVER_HOST=localhost
    export API_SERVER_PORT=8000
    export MANAGEMENT_PORT=8080
    export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/bff_service"
    export PYTHONPATH="$PROJECT_ROOT"
    
    # Build pytest command
    pytest_cmd="uv run pytest tests/integration/"
    
    if [[ "$VERBOSE" == "true" ]]; then
        pytest_cmd="$pytest_cmd -v"
    fi
    
    if [[ -n "$TEST_PATTERN" ]]; then
        pytest_cmd="$pytest_cmd -k '$TEST_PATTERN'"
    fi
    
    pytest_cmd="$pytest_cmd --tb=short -m 'integration and requires_docker' --maxfail=5"
    
    print_status "Running: $pytest_cmd"
    
    if eval "$pytest_cmd"; then
        print_success "Integration tests passed!"
        return 0
    else
        print_error "Integration tests failed!"
        return 1
    fi
}

# Main execution
main() {
    check_prerequisites
    build_packages
    start_docker_stack
    
    if verify_services; then
        if run_tests; then
            print_success "🎉 All integration tests completed successfully!"
            exit 0
        else
            print_error "❌ Integration tests failed"
            exit 1
        fi
    else
        print_error "❌ Service verification failed"
        exit 1
    fi
}

# Run main function
main "$@" 