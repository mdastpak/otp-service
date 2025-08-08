#!/bin/bash

# Deployment script for OTP Service
# Supports different environments with zero-downtime deployment

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DEFAULT_ENVIRONMENT="test"

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

Deploy OTP Service to different environments with zero-downtime strategy.

OPTIONS:
    -e, --environment ENV    Environment (test|production) [default: $DEFAULT_ENVIRONMENT]
    -v, --version VERSION    Version to deploy [required]
    -s, --strategy STRATEGY  Deployment strategy (rolling|blue-green|recreate) [default: rolling]
    --health-timeout SECS    Health check timeout in seconds [default: 300]
    --rollback              Rollback to previous version
    --dry-run               Show what would be deployed without executing
    --force                 Force deployment without confirmations
    --backup                Create backup before deployment
    -h, --help              Show this help message

EXAMPLES:
    $0 -e production -v 1.0.0                    # Deploy version 1.0.0 to production
    $0 -e test -v latest --dry-run               # Dry run deployment to test
    $0 -e production --rollback                  # Rollback production to previous version
    $0 -e production -v 1.0.1 -s blue-green     # Blue-green deployment

ENVIRONMENT VARIABLES:
    DOCKER_REGISTRY         Docker registry URL
    DOCKER_NAMESPACE        Docker namespace/organization
    BACKUP_RETENTION_DAYS   Days to retain backups [default: 7]
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
VERSION=""
STRATEGY="rolling"
HEALTH_TIMEOUT=300
ROLLBACK=false
DRY_RUN=false
FORCE=false
BACKUP=false

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
        -s|--strategy)
            STRATEGY="$2"
            shift 2
            ;;
        --health-timeout)
            HEALTH_TIMEOUT="$2"
            shift 2
            ;;
        --rollback)
            ROLLBACK=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --backup)
            BACKUP=true
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

# Validate strategy
if [[ ! "$STRATEGY" =~ ^(rolling|blue-green|recreate)$ ]]; then
    log_error "Invalid deployment strategy: $STRATEGY"
    exit 1
fi

# Check version requirement
if [[ -z "$VERSION" && "$ROLLBACK" != true ]]; then
    log_error "Version is required for deployment (use -v or --version)"
    exit 1
fi

# Docker configuration
DOCKER_REGISTRY="${DOCKER_REGISTRY:-}"
DOCKER_NAMESPACE="${DOCKER_NAMESPACE:-otp-service}"
IMAGE_NAME="${DOCKER_NAMESPACE}/otp-service"

if [[ -n "$DOCKER_REGISTRY" ]]; then
    IMAGE_NAME="${DOCKER_REGISTRY}/${IMAGE_NAME}"
fi

# Change to project directory
cd "$PROJECT_DIR"

# Determine compose files based on environment
COMPOSE_FILES="-f docker-compose.yml"
case "$ENVIRONMENT" in
    test)
        # Test mode uses default override file (automatically loaded)
        ;;
    production)
        COMPOSE_FILES+=" -f docker-compose.production.yml"
        ;;
esac

# Health check function
check_service_health() {
    local service_url="$1"
    local timeout="$2"
    local interval=5
    local elapsed=0
    
    log_info "Checking service health at $service_url"
    
    while [[ $elapsed -lt $timeout ]]; do
        if curl -f -s "$service_url" >/dev/null 2>&1; then
            log_success "Service is healthy"
            return 0
        fi
        
        sleep $interval
        elapsed=$((elapsed + interval))
        log_info "Health check failed, retrying in ${interval}s... (${elapsed}/${timeout}s)"
    done
    
    log_error "Service health check timeout after ${timeout}s"
    return 1
}

# Backup function
create_backup() {
    if [[ "$BACKUP" == true && "$ENVIRONMENT" == "production" ]]; then
        log_info "Creating backup..."
        
        local backup_dir="backups/$(date +%Y%m%d-%H%M%S)"
        mkdir -p "$backup_dir"
        
        # Backup Redis data
        docker-compose $COMPOSE_FILES exec -T redis redis-cli BGSAVE
        docker cp "$(docker-compose $COMPOSE_FILES ps -q redis)":/data/dump.rdb "$backup_dir/"
        
        # Backup configuration
        cp -r config "$backup_dir/"
        
        # Backup environment files
        cp .env.* "$backup_dir/" 2>/dev/null || true
        
        log_success "Backup created in $backup_dir"
        
        # Clean old backups
        local retention_days=${BACKUP_RETENTION_DAYS:-7}
        find backups -type d -mtime +$retention_days -exec rm -rf {} + 2>/dev/null || true
    fi
}

# Rollback function
rollback_deployment() {
    log_info "Rolling back to previous version..."
    
    # Get the previous version from Docker images
    local previous_version=$(docker images "$IMAGE_NAME" --format "table {{.Tag}}" | grep -v "latest" | head -2 | tail -1)
    
    if [[ -z "$previous_version" ]]; then
        log_error "No previous version found for rollback"
        exit 1
    fi
    
    log_info "Rolling back to version: $previous_version"
    VERSION="$previous_version"
    
    # Proceed with deployment using previous version
    deploy_service
}

# Rolling deployment
deploy_rolling() {
    log_info "Starting rolling deployment..."
    
    # Scale up new version
    docker-compose $COMPOSE_FILES up -d --scale otp-service=2
    
    # Wait for new instances to be healthy
    sleep 10
    check_service_health "http://localhost:${SERVER_PORT:-8080}/health" 60
    
    # Scale down old version
    docker-compose $COMPOSE_FILES up -d --scale otp-service=1
    
    log_success "Rolling deployment completed"
}

# Blue-green deployment
deploy_blue_green() {
    log_info "Starting blue-green deployment..."
    
    # Deploy to green environment
    export ENVIRONMENT_SUFFIX="_green"
    docker-compose $COMPOSE_FILES up -d
    
    # Health check green environment
    check_service_health "http://localhost:${SERVER_PORT:-8080}/health" $HEALTH_TIMEOUT
    
    # Switch traffic (would need load balancer configuration)
    log_info "Switching traffic to green environment"
    
    # Stop blue environment
    export ENVIRONMENT_SUFFIX="_blue"
    docker-compose $COMPOSE_FILES down
    
    # Rename green to blue for next deployment
    unset ENVIRONMENT_SUFFIX
    
    log_success "Blue-green deployment completed"
}

# Recreate deployment
deploy_recreate() {
    log_info "Starting recreate deployment..."
    
    docker-compose $COMPOSE_FILES down
    docker-compose $COMPOSE_FILES up -d
    
    check_service_health "http://localhost:${SERVER_PORT:-8080}/health" $HEALTH_TIMEOUT
    
    log_success "Recreate deployment completed"
}

# Main deployment function
deploy_service() {
    local image_tag="${IMAGE_NAME}:${VERSION}"
    
    log_info "Deploying OTP Service"
    log_info "Environment: $ENVIRONMENT"
    log_info "Version: $VERSION"
    log_info "Strategy: $STRATEGY"
    log_info "Image: $image_tag"
    
    # Dry run mode
    if [[ "$DRY_RUN" == true ]]; then
        log_warning "DRY RUN MODE - No changes will be made"
        log_info "Would deploy: $image_tag"
        log_info "Compose files: $COMPOSE_FILES"
        return 0
    fi
    
    # Confirmation for production
    if [[ "$ENVIRONMENT" == "production" && "$FORCE" != true ]]; then
        echo -n "Deploy to PRODUCTION environment? (yes/no): "
        read -r confirmation
        if [[ "$confirmation" != "yes" ]]; then
            log_info "Deployment cancelled"
            exit 0
        fi
    fi
    
    # Pull latest image
    log_info "Pulling image: $image_tag"
    docker pull "$image_tag"
    
    # Set image in environment
    export BUILD_VERSION="$VERSION"
    export ENVIRONMENT="$ENVIRONMENT"
    
    # Create backup
    create_backup
    
    # Execute deployment based on strategy
    case "$STRATEGY" in
        rolling)
            deploy_rolling
            ;;
        blue-green)
            deploy_blue_green
            ;;
        recreate)
            deploy_recreate
            ;;
    esac
    
    # Post-deployment verification
    log_info "Running post-deployment verification..."
    
    # Check service status
    docker-compose $COMPOSE_FILES ps
    
    # Final health check
    check_service_health "http://localhost:${SERVER_PORT:-8080}/health" 60
    
    log_success "Deployment completed successfully!"
    log_info "Deployed version: $VERSION"
    log_info "Environment: $ENVIRONMENT"
}

# Main execution
log_info "OTP Service Deployment Script"

if [[ "$ROLLBACK" == true ]]; then
    rollback_deployment
else
    deploy_service
fi