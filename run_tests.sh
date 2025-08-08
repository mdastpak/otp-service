#!/bin/bash

# Test runner script for OTP Service
# Runs unit tests and integration tests with proper Redis setup

set -e

echo "🧪 OTP Service Test Runner"
echo "=========================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    printf "${BLUE}[INFO]${NC} %s\n" "$1"
}

log_success() {
    printf "${GREEN}[SUCCESS]${NC} %s\n" "$1"
}

log_error() {
    printf "${RED}[ERROR]${NC} %s\n" "$1"
}

# Function to check if Redis is running
check_redis() {
    if docker-compose ps redis | grep -q "Up"; then
        return 0
    else
        return 1
    fi
}

# Function to run unit tests
run_unit_tests() {
    log_info "Running unit tests..."
    if go test -v -race ./internal/...; then
        log_success "Unit tests passed!"
    else
        log_error "Unit tests failed!"
        return 1
    fi
}

# Function to run integration tests
run_integration_tests() {
    log_info "Starting Redis for integration tests..."
    docker-compose up -d redis
    
    # Wait for Redis to be ready
    log_info "Waiting for Redis to be ready..."
    sleep 5
    
    # Verify Redis is running
    if ! check_redis; then
        log_error "Redis failed to start"
        docker-compose down
        return 1
    fi
    
    log_info "Running integration tests..."
    # Run tests from within the tests directory
    if (cd tests && go test -v -race .); then
        log_success "Integration tests passed!"
        docker-compose down
        return 0
    else
        log_error "Integration tests failed!"
        docker-compose down
        return 1
    fi
}

# Main execution
main() {
    # Check if we're in the right directory
    if [[ ! -f "go.mod" ]]; then
        log_error "Please run this script from the project root directory"
        exit 1
    fi
    
    # Run unit tests first
    if ! run_unit_tests; then
        exit 1
    fi
    
    # Run integration tests if Docker is available
    if command -v docker-compose >/dev/null 2>&1; then
        if ! run_integration_tests; then
            exit 1
        fi
    else
        log_info "Docker Compose not found, skipping integration tests"
    fi
    
    log_success "All tests completed successfully! 🎉"
}

# Run the main function
main "$@"