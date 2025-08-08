#!/bin/bash

# Test data seeding script for OTP Service
# Seeds Redis with test data for development and testing

set -e

# Configuration
REDIS_HOST="${REDIS_HOST:-redis-test}"
REDIS_PORT="${REDIS_PORT:-6379}"
REDIS_PASSWORD="${REDIS_PASSWORD:-}"
KEY_PREFIX="${REDIS_KEY_PREFIX:-otp:test:}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Redis command wrapper
redis_cmd() {
    local cmd="$1"
    if [[ -n "$REDIS_PASSWORD" ]]; then
        redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" -a "$REDIS_PASSWORD" --no-auth-warning $cmd
    else
        redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" $cmd
    fi
}

# Wait for Redis to be available
wait_for_redis() {
    local max_attempts=30
    local attempt=1
    
    log_info "Waiting for Redis to be available at $REDIS_HOST:$REDIS_PORT..."
    
    while [[ $attempt -le $max_attempts ]]; do
        if redis_cmd "ping" >/dev/null 2>&1; then
            log_success "Redis is available"
            return 0
        fi
        
        log_info "Attempt $attempt/$max_attempts: Redis not ready, waiting..."
        sleep 2
        attempt=$((attempt + 1))
    done
    
    log_error "Redis is not available after $max_attempts attempts"
    return 1
}

# Clear existing test data
clear_test_data() {
    log_info "Clearing existing test data..."
    
    # Get all keys with test prefix
    local keys=$(redis_cmd "KEYS ${KEY_PREFIX}*" 2>/dev/null || echo "")
    
    if [[ -n "$keys" ]]; then
        echo "$keys" | while read -r key; do
            if [[ -n "$key" ]]; then
                redis_cmd "DEL $key" >/dev/null
            fi
        done
        log_success "Cleared existing test data"
    else
        log_info "No existing test data to clear"
    fi
}

# Seed test OTPs
seed_test_otps() {
    log_info "Seeding test OTP data..."
    
    # Test user accounts with known OTPs
    local test_accounts=(
        "test1@example.com:123456:300"
        "test2@example.com:654321:300"
        "admin@example.com:999999:600"
        "user@example.com:111111:300"
        "demo@example.com:888888:300"
    )
    
    for account_data in "${test_accounts[@]}"; do
        IFS=':' read -r email otp expiry <<< "$account_data"
        local key="${KEY_PREFIX}${email}"
        
        # Store OTP with expiry
        redis_cmd "SET $key $otp EX $expiry" >/dev/null
        
        # Store metadata for testing
        local meta_key="${key}:meta"
        redis_cmd "HSET $meta_key email $email otp $otp expiry $expiry attempts 0 created $(date +%s)" >/dev/null
        
        log_info "Seeded OTP for $email: $otp (expires in ${expiry}s)"
    done
    
    log_success "Test OTPs seeded successfully"
}

# Seed rate limiting test data
seed_rate_limit_data() {
    log_info "Seeding rate limiting test data..."
    
    # Simulate some API usage for rate limiting tests
    local rate_limit_keys=(
        "rate_limit:127.0.0.1:5"
        "rate_limit:192.168.1.100:10"
        "rate_limit:10.0.0.1:15"
    )
    
    for key_data in "${rate_limit_keys[@]}"; do
        IFS=':' read -r prefix ip count <<< "$key_data"
        local key="rate_limit:${ip}"
        
        redis_cmd "SET $key $count EX 60" >/dev/null
        log_info "Set rate limit for $ip: $count requests"
    done
    
    log_success "Rate limiting test data seeded"
}

# Seed metrics test data
seed_metrics_data() {
    log_info "Seeding metrics test data..."
    
    # Simulate some metrics counters
    local metrics=(
        "otp_generated_total:50"
        "otp_verified_total:45"
        "otp_failed_total:5"
        "otp_expired_total:8"
    )
    
    for metric_data in "${metrics[@]}"; do
        IFS=':' read -r metric value <<< "$metric_data"
        local key="metrics:${metric}"
        
        redis_cmd "SET $key $value" >/dev/null
        log_info "Set metric $metric: $value"
    done
    
    log_success "Metrics test data seeded"
}

# Seed expired OTPs for cleanup testing
seed_expired_otps() {
    log_info "Seeding expired OTPs for cleanup testing..."
    
    local expired_accounts=(
        "expired1@example.com:111111"
        "expired2@example.com:222222"
        "expired3@example.com:333333"
    )
    
    for account_data in "${expired_accounts[@]}"; do
        IFS=':' read -r email otp <<< "$account_data"
        local key="${KEY_PREFIX}${email}"
        
        # Set with very short expiry (1 second)
        redis_cmd "SET $key $otp EX 1" >/dev/null
        
        local meta_key="${key}:meta"
        redis_cmd "HSET $meta_key email $email otp $otp expiry 1 attempts 0 created $(date +%s)" >/dev/null
        
        log_info "Seeded expired OTP for $email: $otp"
    done
    
    # Wait for them to expire
    sleep 2
    
    log_success "Expired OTPs seeded for cleanup testing"
}

# Verify seeded data
verify_seeded_data() {
    log_info "Verifying seeded data..."
    
    # Count total keys
    local total_keys=$(redis_cmd "KEYS ${KEY_PREFIX}*" | wc -l)
    log_info "Total keys with prefix '${KEY_PREFIX}': $total_keys"
    
    # Verify some test OTPs
    local test_email="test1@example.com"
    local key="${KEY_PREFIX}${test_email}"
    local otp=$(redis_cmd "GET $key" 2>/dev/null || echo "")
    
    if [[ -n "$otp" ]]; then
        log_success "Verification passed: Found OTP for $test_email"
    else
        log_warning "Verification failed: No OTP found for $test_email"
    fi
    
    # Show Redis info
    log_info "Redis database info:"
    redis_cmd "INFO keyspace" | grep "db"
}

# Main execution
main() {
    log_info "Starting test data seeding for OTP Service"
    log_info "Redis: $REDIS_HOST:$REDIS_PORT"
    log_info "Key prefix: $KEY_PREFIX"
    
    # Wait for Redis
    wait_for_redis
    
    # Clear and seed data
    clear_test_data
    seed_test_otps
    seed_rate_limit_data
    seed_metrics_data
    seed_expired_otps
    
    # Verify
    verify_seeded_data
    
    log_success "Test data seeding completed successfully!"
    log_info "You can now run tests against the seeded data"
    
    # Show some useful test commands
    cat << EOF

TEST COMMANDS:
# Test OTP generation (POST to root path /)
curl -X POST "http://localhost:8080/?ttl=300&retry_limit=5&code_length=6" -H "Content-Type: application/json"

# Test OTP verification with seeded data (GET from root path /)
curl -X GET "http://localhost:8080/?uuid=YOUR_UUID_HERE&otp=123456"

# Check health
curl http://localhost:8080/health

EOF
}

# Execute main function
main "$@"