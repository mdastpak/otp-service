#!/bin/bash
# scripts/build.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Print step function
print_step() {
    echo -e "${YELLOW}==> $1${NC}"
}

# Check if Docker is running
check_docker() {
    if ! docker info > /dev/null 2>&1; then
        echo -e "${RED}Error: Docker is not running or not accessible${NC}"
        exit 1
    fi
}

# Main build function
main() {
    print_step "Starting build process..."

    # Check Docker
    print_step "Checking Docker..."
    check_docker

    # Clean old builds
    print_step "Cleaning old builds..."
    docker-compose down --volumes --remove-orphans || true

    # Build new images
    print_step "Building Docker images..."
    docker-compose build --no-cache

    print_step "Running tests..."
    go test -v ./...

    print_step "Checking for vulnerabilities..."
    go vet ./...

    echo -e "${GREEN}Build completed successfully!${NC}"
    echo -e "${YELLOW}To start the service, run: ./scripts/deploy.sh${NC}"
}

main "$@"