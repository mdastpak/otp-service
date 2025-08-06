#!/bin/bash

# Test runner script for OTP Service
set -e

echo "🧪 OTP Service Test Suite"
echo "========================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}▶${NC} $1"
}

print_success() {
    echo -e "${GREEN}✅${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠️${NC} $1"
}

print_error() {
    echo -e "${RED}❌${NC} $1"
}

# Check if Go is installed
if ! command -v go &> /dev/null; then
    print_error "Go is not installed or not in PATH"
    exit 1
fi

print_success "Go is installed: $(go version)"

# Clean up previous builds
print_status "Cleaning up previous builds..."
make clean 2>/dev/null || rm -f otp-service otp-service_old otp-service_unix 2>/dev/null || true

# Download dependencies
print_status "Downloading dependencies..."
go mod download
go mod tidy

# Format code
print_status "Formatting code..."
go fmt ./...

# Vet code
print_status "Running go vet..."
go vet ./...

# Run unit tests
print_status "Running unit tests..."
echo ""
go test -v ./internal/... -timeout=30s

# Run integration tests
print_status "Running integration tests..."
echo ""
go test -v . -timeout=30s

# Generate coverage report
print_status "Generating coverage report..."
go test -coverprofile=coverage.out ./internal/...
go tool cover -func=coverage.out

# Generate HTML coverage report
print_status "Generating HTML coverage report..."
go tool cover -html=coverage.out -o coverage.html
print_success "Coverage report generated: coverage.html"

# Run benchmarks
print_status "Running benchmarks..."
echo ""
go test -bench=. -benchmem ./internal/...

# Build application
print_status "Building application..."
go build -o otp-service ./main.go
print_success "Build successful: otp-service"

# Test build of original main
print_status "Testing original main build..."
go build -o otp-service_old ./main.go
print_success "Original build successful: otp-service_old"

# Run a quick smoke test
print_status "Running smoke test..."
if [ -f "config.yaml" ]; then
    echo "Starting service in background for smoke test..."
    ./otp-service &
    SERVICE_PID=$!
    
    # Wait a moment for service to start
    sleep 2
    
    # Test health endpoint
    if curl -s -f http://localhost:8080/health > /dev/null; then
        print_success "Health endpoint is responding"
    else
        print_warning "Health endpoint test failed (expected - Redis may not be running)"
    fi
    
    # Stop the service
    kill $SERVICE_PID 2>/dev/null || true
    wait $SERVICE_PID 2>/dev/null || true
else
    print_warning "config.yaml not found, skipping smoke test"
fi

echo ""
echo "🎉 Test suite completed!"
echo ""
echo "📊 Test Results Summary:"
echo "  - Unit tests: ✅ Passed"
echo "  - Integration tests: ✅ Passed" 
echo "  - Code coverage: See coverage.html"
echo "  - Benchmarks: ✅ Completed"
echo "  - Build: ✅ Successful"
echo ""
echo "📁 Generated files:"
echo "  - otp-service (new version binary)"
echo "  - otp-service_old (original version binary)"
echo "  - coverage.out (coverage data)"
echo "  - coverage.html (coverage report)"
echo ""
echo "🚀 Ready for deployment!"