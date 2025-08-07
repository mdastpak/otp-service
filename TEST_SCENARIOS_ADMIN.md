# Admin Panel Access Test Scenarios

This document outlines comprehensive test scenarios for the admin panel access control system, covering both production and test modes.

## 📋 Test Coverage Overview

### ✅ Test Categories Covered:
- **IP Whitelist Validation** - Production vs Test mode
- **JWT Token Authentication** - Valid, expired, malformed tokens
- **Login Functionality** - Credential validation, response format
- **Redirect Behavior** - Automatic routing based on auth state  
- **Test Mode Bypasses** - Security bypass validation
- **Edge Cases** - Malformed requests, rate limiting, token formats

---

## 🏭 Production Mode Test Scenarios

### 1. IP Whitelist Tests (`TestProductionModeAdminAccess`)

#### ✅ Valid IP Scenarios:
```go
// Whitelisted IP (192.168.1.100) → Show login page
// Localhost (127.0.0.1, ::1) → Show login page  
// Expected: HTTP 200, Login page content
```

#### ❌ Invalid IP Scenarios:
```go
// Non-whitelisted IP (203.0.113.1) → Show restriction page
// Private IP not in whitelist → Show restriction page
// Expected: HTTP 403, "Access Restricted" page with client IP
```

**Test Function**: `testProductionIPWhitelist(t *testing.T)`
- Validates IP whitelist enforcement
- Checks restriction page displays client IP
- Confirms proper logging of unauthorized attempts

### 2. JWT Token Validation Tests

#### ✅ Valid JWT Token:
```go
// Valid token with authorized IP → Redirect to dashboard
// Expected: HTTP 302, Location: "/admin/dashboard"
```

#### ❌ Invalid JWT Scenarios:
```go
// Expired token → Show login page (HTTP 200)
// Malformed token → Show login page (HTTP 200)  
// No token → Show login page (HTTP 200)
```

**Test Function**: `testProductionJWTValidation(t *testing.T)`
- Tests token validation logic
- Verifies redirect behavior for valid tokens
- Confirms fallback to login for invalid tokens

### 3. Login Functionality Tests

#### ✅ Valid Login:
```go
POST /admin/auth/login
{
  "username": "admin",
  "password": "admin123"
}
// Expected: HTTP 200, JWT token in response
```

#### ❌ Invalid Login:
```go
POST /admin/auth/login  
{
  "username": "admin",
  "password": "wrongpassword"
}
// Expected: HTTP 401, "Invalid credentials"
```

#### ❌ IP Blocked Login:
```go
// Login from non-whitelisted IP
// Expected: HTTP 403, "Access denied: IP not authorized"
```

**Test Function**: `testProductionLogin(t *testing.T)`
- Validates credential verification
- Tests JWT token generation
- Confirms IP whitelist applies to auth endpoints

### 4. Dashboard Access & Redirects

#### ✅ Authenticated Access:
```go
GET /admin/dashboard
Authorization: Bearer <valid_token>
X-Forwarded-For: <whitelisted_ip>
// Expected: HTTP 200, dashboard content
```

#### ❌ Unauthenticated Access:
```go  
GET /admin/dashboard (no token)
// Expected: HTTP 401, "Authorization token required"

GET /admin/dashboard  
Authorization: Bearer <expired_token>
// Expected: HTTP 401, "Invalid or expired token"
```

**Test Function**: `testProductionRedirects(t *testing.T)`

---

## 🧪 Test Mode Scenarios

### 1. Security Bypass Tests (`TestTestModeAdminAccess`)

#### ✅ IP Whitelist Bypass:
```go
GET /admin
X-Forwarded-For: 203.0.113.1 (non-whitelisted)
// Expected: HTTP 200, login page (IP bypass successful)
```

#### ✅ JWT Bypass:
```go
GET /admin/dashboard (no JWT token)
X-Forwarded-For: 203.0.113.1 (non-whitelisted)  
// Expected: HTTP 200, dashboard content (JWT bypass successful)
```

#### ✅ Login from Any IP:
```go
POST /admin/auth/login from any IP
// Expected: HTTP 200, successful login
```

**Test Function**: `testModeBypass(t *testing.T)`

### 2. Test Mode Credentials

#### ✅ Random Credential Generation:
```go
// Verify testModeCredentials generated
// Username format: admin_<hexstring>
// Password format: <hexstring>
// Both should be non-empty
```

#### ✅ Test Credentials Login:
```go
POST /admin/auth/login
{
  "username": "<generated_username>", 
  "password": "<generated_password>"
}
// Expected: HTTP 200, valid JWT token
```

#### ✅ Regular Credentials Still Work:
```go
POST /admin/auth/login
{
  "username": "admin",
  "password": "admin123" 
}
// Expected: HTTP 200, valid JWT token
```

**Test Function**: `testModeCredentials(t *testing.T)`

---

## 🔍 Edge Case Test Scenarios

### 1. Malformed JWT Tokens (`TestAdminAccessEdgeCases`)

```go
// Test various malformed tokens:
- "not.a.jwt"
- "Bearer invalid"  
- Very long token (1000+ chars)
- Empty string ""
- Whitespace only " "

// All should result in: HTTP 401
```

### 2. Token Location Tests

#### ✅ Multiple Token Sources:
```go
// Authorization header: "Bearer <token>"
// Query parameter: "?token=<token>"
// Cookie: "admin_token=<token>" (if implemented)

// All valid locations should work for authentication
```

### 3. Rate Limiting

```go
// Verify rate limiting middleware doesn't block legitimate requests
// Expected: Not HTTP 429 for normal request rates
```

---

## ⚡ Performance Benchmarks

### 1. IP Whitelist Performance (`BenchmarkAdminAccessControl`)

```go
BenchmarkAdminAccessControl/IPWhitelistCheck
// Measures IP validation performance
// Should complete in microseconds
```

### 2. JWT Validation Performance

```go  
BenchmarkAdminAccessControl/JWTValidation
// Measures JWT parsing and validation speed
// Should complete in microseconds
```

---

## 🧾 Test Execution Instructions

### Run All Admin Access Tests:
```bash
go test -v ./internal/admin/ -run "TestProductionModeAdminAccess|TestTestModeAdminAccess|TestAdminAccessEdgeCases"
```

### Run Specific Test Categories:
```bash
# Production mode tests only
go test -v ./internal/admin/ -run "TestProductionModeAdminAccess"

# Test mode tests only  
go test -v ./internal/admin/ -run "TestTestModeAdminAccess"

# Edge cases only
go test -v ./internal/admin/ -run "TestAdminAccessEdgeCases"
```

### Run Performance Benchmarks:
```bash
go test -v ./internal/admin/ -bench="BenchmarkAdminAccessControl" -benchmem
```

### Run with Coverage:
```bash
go test -v ./internal/admin/ -coverprofile=coverage.out
go tool cover -html=coverage.out -o coverage.html
```

---

## 📊 Expected Test Results

### ✅ Successful Test Run Output:
```
=== RUN   TestProductionModeAdminAccess
=== RUN   TestProductionModeAdminAccess/ProductionMode_IPWhitelist_Tests  
=== RUN   TestProductionModeAdminAccess/ProductionMode_JWT_Tests
=== RUN   TestProductionModeAdminAccess/ProductionMode_Login_Tests
=== RUN   TestProductionModeAdminAccess/ProductionMode_Redirect_Tests
--- PASS: TestProductionModeAdminAccess (0.05s)

=== RUN   TestTestModeAdminAccess
=== RUN   TestTestModeAdminAccess/TestMode_Bypass_Tests
=== RUN   TestTestModeAdminAccess/TestMode_Credentials_Tests  
--- PASS: TestTestModeAdminAccess (0.03s)

=== RUN   TestAdminAccessEdgeCases
--- PASS: TestAdminAccessEdgeCases (0.02s)

PASS
ok      otp-service/internal/admin    0.105s
```

### 📈 Coverage Targets:
- **IP Whitelist Logic**: 100% coverage
- **JWT Validation**: 100% coverage  
- **Login Flow**: 100% coverage
- **Redirect Logic**: 100% coverage
- **Test Mode Bypasses**: 100% coverage

---

## 🔒 Security Test Validation

### Production Mode Security Checklist:
- [ ] ❌ Non-whitelisted IPs cannot access admin routes
- [ ] ❌ Invalid/expired JWT tokens are rejected  
- [ ] ❌ Login attempts from unauthorized IPs are blocked
- [ ] ✅ Valid tokens allow dashboard access
- [ ] ✅ Restriction page shows proper error messages
- [ ] ✅ All unauthorized attempts are logged

### Test Mode Security Checklist:
- [ ] ✅ IP whitelist is completely bypassed
- [ ] ✅ JWT validation is bypassed for dashboard
- [ ] ✅ Random credentials are generated and logged
- [ ] ✅ Both test and regular credentials work
- [ ] ✅ All bypasses are properly logged for audit

---

## 🚨 Critical Test Scenarios

### Must-Pass Security Tests:
1. **IP Restriction Enforcement** - Non-whitelisted IPs must be blocked in production
2. **JWT Expiration** - Expired tokens must be rejected  
3. **Credential Validation** - Wrong passwords must fail
4. **Test Mode Isolation** - Bypasses only work in test mode
5. **Audit Logging** - All access attempts must be logged

### Must-Pass Functionality Tests:
1. **Login Flow** - Valid credentials → JWT token → Dashboard access
2. **Redirect Logic** - Authenticated users go to dashboard, others to login  
3. **Token Persistence** - JWT tokens work across requests
4. **Error Handling** - Proper error messages for all failure cases

---

## 📝 Test Maintenance

### When to Update Tests:
- IP whitelist logic changes
- JWT token structure modifications
- New authentication methods added
- Security middleware updates
- Route structure changes

### Test Data Management:
- JWT secrets rotated for tests only
- Test IP addresses documented
- Token expiration times appropriate for testing
- Test credentials clearly marked

This comprehensive test suite ensures the admin panel access control system works correctly in both production and test environments while maintaining proper security boundaries.