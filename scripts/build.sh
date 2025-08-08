#!/bin/bash

# Build script for OTP Service Docker containers
# Supports multiple environments and build modes

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DEFAULT_ENVIRONMENT="test"
DEFAULT_VERSION="latest"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Help function
show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

Build Docker containers for OTP Service with different configurations.

OPTIONS:
    -e, --environment ENV    Environment (test|production) [default: $DEFAULT_ENVIRONMENT]
    -v, --version VERSION    Build version tag [default: $DEFAULT_VERSION]
    -t, --target TARGET      Build target (test|production) [default: auto-detect from environment]
    -p, --push              Push images to registry after build
    -c, --clean             Clean build (no cache)
    -q, --quiet             Quiet mode (less output)
    --parallel              Build with parallel processing
    --security-scan         Run security scan after build
    --test                  Run tests after build
    -h, --help              Show this help message

EXAMPLES:
    $0                                          # Build test environment (default)
    $0 -e production -v 1.0.0                 # Build production with version
    $0 -e test --test --security-scan          # Build test with tests and security scan
    $0 -e production -v 1.0.0 -p --clean      # Clean production build and push

ENVIRONMENT VARIABLES:
    BUILD_VERSION           Override version (same as -v)
    BUILD_COMMIT            Git commit hash (auto-detected)
    BUILD_DATE              Build date (auto-detected)
    DOCKER_REGISTRY         Docker registry URL
    DOCKER_NAMESPACE        Docker namespace/organization
EOF
}

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" >&2
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" >&2
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Parse command line arguments
ENVIRONMENT="$DEFAULT_ENVIRONMENT"
VERSION="$DEFAULT_VERSION"
TARGET=""
PUSH=false
CLEAN=false
QUIET=false
PARALLEL=false
SECURITY_SCAN=false
RUN_TESTS=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -e|--environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        -v|--version)
            VERSION="$2"
            shift 2
            ;;
        -t|--target)
            TARGET="$2"
            shift 2
            ;;
        -p|--push)
            PUSH=true
            shift
            ;;
        -c|--clean)
            CLEAN=true
            shift
            ;;
        -q|--quiet)
            QUIET=true
            shift
            ;;
        --parallel)
            PARALLEL=true
            shift
            ;;
        --security-scan)
            SECURITY_SCAN=true
            shift
            ;;
        --test)
            RUN_TESTS=true
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Validate environment
if [[ ! "$ENVIRONMENT" =~ ^(test|production)$ ]]; then
    log_error "Invalid environment: $ENVIRONMENT"
    log_error "Valid options: test, production"
    exit 1
fi

# Auto-detect target if not specified
if [[ -z "$TARGET" ]]; then
    case "$ENVIRONMENT" in
        test) TARGET="test" ;;
        production) TARGET="production" ;;
    esac
fi

# Set build arguments
BUILD_VERSION="${BUILD_VERSION:-$VERSION}"
BUILD_COMMIT="${BUILD_COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')}"
BUILD_DATE="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

# Docker registry configuration
DOCKER_REGISTRY="${DOCKER_REGISTRY:-}"
DOCKER_NAMESPACE="${DOCKER_NAMESPACE:-otp-service}"
IMAGE_NAME="${DOCKER_NAMESPACE}/otp-service"

if [[ -n "$DOCKER_REGISTRY" ]]; then
    IMAGE_NAME="${DOCKER_REGISTRY}/${IMAGE_NAME}"
fi

IMAGE_TAG="${IMAGE_NAME}:${BUILD_VERSION}"
ENVIRONMENT_TAG="${IMAGE_NAME}:${ENVIRONMENT}-${BUILD_VERSION}"

# Change to project directory
cd "$PROJECT_DIR"

log_info "Building OTP Service Docker containers"
log_info "Environment: $ENVIRONMENT"
log_info "Target: $TARGET"
log_info "Version: $BUILD_VERSION"
log_info "Commit: $BUILD_COMMIT"
log_info "Date: $BUILD_DATE"
log_info "Image: $IMAGE_TAG"

# Build arguments
BUILD_ARGS=(
    --build-arg "BUILD_MODE=$TARGET"
    --build-arg "BUILD_VERSION=$BUILD_VERSION"
    --build-arg "BUILD_COMMIT=$BUILD_COMMIT"
    --build-arg "BUILD_DATE=$BUILD_DATE"
)

if [[ "$CLEAN" == true ]]; then
    BUILD_ARGS+=(--no-cache)
    log_info "Clean build enabled (no cache)"
fi

if [[ "$QUIET" == true ]]; then
    BUILD_ARGS+=(--quiet)
fi

# Docker build command
DOCKER_CMD="docker build"
if [[ "$PARALLEL" == true ]]; then
    export DOCKER_BUILDKIT=1
    log_info "Parallel build enabled (BuildKit)"
fi

# Build the image
log_info "Building Docker image..."
$DOCKER_CMD "${BUILD_ARGS[@]}" -t "$IMAGE_TAG" -t "$ENVIRONMENT_TAG" .

if [[ $? -eq 0 ]]; then
    log_success "Docker image built successfully: $IMAGE_TAG"
else
    log_error "Docker build failed"
    exit 1
fi

# Run security scan
if [[ "$SECURITY_SCAN" == true ]]; then
    log_info "Running security scan..."
    if command -v trivy >/dev/null 2>&1; then
        trivy image --exit-code 0 --severity HIGH,CRITICAL "$IMAGE_TAG"
    elif command -v docker >/dev/null 2>&1; then
        docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
            aquasec/trivy:latest image --exit-code 0 --severity HIGH,CRITICAL "$IMAGE_TAG"
    else
        log_warning "Security scanner not found (trivy). Skipping security scan."
    fi
fi

# Run tests
if [[ "$RUN_TESTS" == true ]]; then
    log_info "Running tests..."
    # Start Redis for integration tests
    docker-compose up -d redis
    sleep 5
    
    # Run all tests
    go test -v -race ./... && go test -v -race ./tests/...
    test_result=$?
    
    # Cleanup
    docker-compose down
    
    if [[ $test_result -eq 0 ]]; then
        log_success "Tests passed"
    else
        log_error "Tests failed"
        exit 1
    fi
fi

# Push to registry
if [[ "$PUSH" == true ]]; then
    log_info "Pushing image to registry..."
    docker push "$IMAGE_TAG"
    docker push "$ENVIRONMENT_TAG"
    
    if [[ $? -eq 0 ]]; then
        log_success "Images pushed successfully"
    else
        log_error "Failed to push images"
        exit 1
    fi
fi

# Summary
log_success "Build completed successfully!"
log_info "Built images:"
log_info "  - $IMAGE_TAG"
log_info "  - $ENVIRONMENT_TAG"

if [[ "$PUSH" == true ]]; then
    log_info "Images have been pushed to registry"
fi

# Show image size
IMAGE_SIZE=$(docker images --format "table {{.Size}}" "$IMAGE_TAG" | tail -n +2)
log_info "Image size: $IMAGE_SIZE"