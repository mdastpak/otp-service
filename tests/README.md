# OTP Service Tests

This directory contains comprehensive tests for the OTP Service covering various scenarios, security aspects, and environment-specific behaviors.

## Test Structure

### Basic Integration Tests (`basic_integration_test.go`)
- **Complete OTP Flow**: Generation → Verification → Cleanup
- **Error Handling**: Invalid OTP, missing parameters, expired tokens
- **CORS**: Cross-origin request handling
- **Health Checks**: Service availability and monitoring
- **Parameter Validation**: Invalid parameter scenarios
- **Security Input Testing**: Basic malicious input handling
- **Environment-specific Testing**: Test vs Production mode differences

## Test Categories

### 🛡️ Security Tests
```bash
make test-security
```

**Coverage:**
- SQL injection attempts with various payloads
- XSS prevention with script injection attempts
- CSRF protection with malicious origins
- Input validation edge cases (Unicode, null bytes, oversized data)
- Timing attack resistance
- Rate limiting bypass attempts
- Security header validation
- Large payload handling
- Concurrent attack scenarios

### 🔄 Integration Tests
```bash
make test-integration
```

**Coverage:**
- End-to-end OTP generation and verification
- Invalid OTP verification scenarios
- Expired OTP handling
- Rate limiting functionality
- CORS header validation
- Parameter validation
- Health endpoint testing
- Concurrent request handling

### 🌍 Environment Tests
```bash
make test-env
```

**Coverage:**
- Test vs Production mode differences
- CORS policy variations by environment
- Security header implementation
- Rate limiting differences
- Cross-origin request handling
- Configuration isolation
- Error handling variations

## Running Tests

### All Tests
```bash
make test
# or
./run_tests.sh
```

### Specific Test Suites
```bash
make test-unit          # Unit tests only
make test-integration   # Integration tests
make test-coverage      # Tests with coverage report
```

### Manual Test Execution
```bash
# Unit tests only
go test -v -race ./internal/...

# Integration tests (requires Redis)
docker-compose up -d redis
go test -v -race ./tests/
docker-compose down

# Specific test functions
go test -v -race ./tests/ -run "TestBasicOTPFlow"
go test -v -race ./tests/ -run "TestSecurityInputs" 
go test -v -race ./tests/ -run "TestProductionModeHeaders"
```

## Test Scenarios Covered

### ✅ Valid Operations
- Standard OTP generation with valid parameters
- Successful OTP verification within expiry time
- Health check endpoint responses
- CORS preflight requests

### ❌ Error Cases
- **Expired OTP**: Verification after TTL expiry
- **Invalid OTP**: Wrong OTP code verification
- **Missing Parameters**: Incomplete request data
- **Invalid Parameters**: Out-of-range values (TTL, retry limit, code length)
- **Rate Limiting**: Exceeding request limits
- **Malformed Requests**: Invalid JSON, binary data

### 🔒 Security Scenarios
- **Injection Attacks**: SQL injection, XSS attempts
- **CSRF Attacks**: Cross-site request forgery
- **Input Attacks**: Unicode, null bytes, oversized payloads
- **Timing Attacks**: Response timing consistency
- **Concurrent Attacks**: Multi-threaded attack scenarios

### 🌐 Environment Scenarios
- **Test Mode**: Permissive CORS, detailed logging
- **Production Mode**: Strict CORS, security headers
- **Cross-Origin**: Different origin handling by mode
- **Configuration**: Environment isolation testing

## Test Data and Mocking

### Redis Integration
- Tests use real Redis connection when available
- Falls back to mocks for CI/CD environments
- Automatic cleanup after each test

### Mock Objects
- `MockRedisClient`: Redis interface mocking
- Request/Response mocking with `httptest`
- Environment variable mocking

### Test Data
- Predefined UUIDs for consistent testing
- Various OTP formats and lengths
- Malicious payloads for security testing
- Edge case inputs for validation testing

## Expected Behaviors

### Test Mode (Default)
- **Port**: 8080 (development/CORS friendly)
- **CORS**: Permissive (`*` origin allowed)
- **Logging**: Verbose debug information
- **Rate Limiting**: More lenient thresholds
- **Validation**: Detailed error messages

### Production Mode
- **Port**: Configurable (typically 80/443 with reverse proxy)
- **CORS**: Strict (specific origins only)
- **Logging**: Structured JSON logging
- **Rate Limiting**: Strict thresholds
- **Security Headers**: Complete security header set
- **Validation**: Minimal error disclosure

## Continuous Integration

### Test Requirements
- Go 1.23.2+
- Redis server (for integration tests)
- Docker and Docker Compose

### Environment Variables
```bash
SKIP_INTEGRATION_TESTS=true  # Skip Redis-dependent tests
REDIS_HOST=localhost         # Redis host for testing
REDIS_PORT=6379             # Redis port for testing
```

### CI Pipeline Integration
```yaml
# Example GitHub Actions
- name: Run Tests
  run: |
    make test-unit
    make test-integration
    make test-security
    make test-coverage
```

## Performance Benchmarks

Tests include benchmark functions for:
- OTP generation performance
- Verification response times
- Concurrent request handling
- Memory allocation patterns

Run with:
```bash
go test -bench=. -benchmem ./tests/
```

## Test Coverage

Target coverage areas:
- **Unit Tests**: 85%+ individual function coverage
- **Integration Tests**: 70%+ end-to-end flow coverage  
- **Security Tests**: 100% attack vector coverage
- **Environment Tests**: 100% configuration coverage

Generate coverage reports:
```bash
make test-coverage
# Open coverage.html in browser
```

## Contributing Test Cases

When adding new features:
1. Add unit tests in `internal/*/` directories
2. Add integration tests in `tests/integration_test.go`
3. Add security tests if security-relevant
4. Add environment tests if behavior differs by mode
5. Update this documentation

### Test Naming Conventions
- `TestFeatureName_Scenario` for unit tests
- `TestIntegration_FeatureScenario` for integration tests  
- `TestSecurity_AttackType` for security tests
- `TestEnvironment_ModeFeature` for environment tests