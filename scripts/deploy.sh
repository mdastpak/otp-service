#!/bin/bash
# scripts/deploy.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Environment variables
ENV=${1:-"production"}
CONFIG_FILE="config/config.yaml"

# Print step function
print_step() {
    echo -e "${YELLOW}==> $1${NC}"
}

# Check prerequisites
check_prerequisites() {
    # Check Docker
    if ! docker info > /dev/null 2>&1; then
        echo -e "${RED}Error: Docker is not running or not accessible${NC}"
        exit 1
    }

    # Check config file
    if [ ! -f "$CONFIG_FILE" ]; then
        echo -e "${RED}Error: Config file not found at $CONFIG_FILE${NC}"
        exit 1
    }
}

# Function to wait for service health
wait_for_service() {
    local service=$1
    local max_attempts=30
    local attempt=1

    print_step "Waiting for $service to be healthy..."
    
    while [ $attempt -le $max_attempts ]; do
        if docker-compose ps | grep $service | grep -q "healthy"; then
            echo -e "${GREEN}$service is healthy!${NC}"
            return 0
        fi
        echo -n "."
        sleep 2
        attempt=$((attempt + 1))
    done

    echo -e "${RED}\nError: $service failed to become healthy${NC}"
    return 1
}

# Deploy function
deploy() {
    print_step "Starting deployment for environment: $ENV"

    # Start services
    print_step "Starting services..."
    docker-compose up -d

    # Wait for Redis
    wait_for_service "otp-redis"
    
    # Wait for OTP service
    wait_for_service "otp-service"

    print_step "Checking service logs..."
    docker-compose logs --tail=50 otp-service

    echo -e "${GREEN}Deployment completed successfully!${NC}"
    echo "Services are running at:"
    echo "- OTP Service: http://localhost:8080"
    echo "- Redis: localhost:6379"
}

# Main function
main() {
    check_prerequisites
    deploy

    # Print endpoints
    print_step "Available endpoints:"
    echo "Health check:   GET    http://localhost:8080/health"
    echo "Generate OTP:   POST   http://localhost:8080/"
    echo "Verify OTP:     GET    http://localhost:8080/"

    echo -e "\n${YELLOW}To check logs:${NC}"
    echo "docker-compose logs -f otp-service"
    echo -e "\n${YELLOW}To stop services:${NC}"
    echo "docker-compose down"
}

main "$@"