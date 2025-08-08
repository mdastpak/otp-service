package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"otp-service/internal/config"
	"otp-service/internal/models"
	"otp-service/internal/redis"
)

// MockRedisClient for middleware tests
type MockRedisClient struct {
	mock.Mock
}

var _ redis.RedisInterface = (*MockRedisClient)(nil)

func (m *MockRedisClient) CheckRateLimit(clientID string) bool {
	args := m.Called(clientID)
	return args.Bool(0)
}

func (m *MockRedisClient) SaveOTP(uuid string, otpData models.OTPRequest) error {
	args := m.Called(uuid, otpData)
	return args.Error(0)
}

func (m *MockRedisClient) GetOTP(uuid string) (*models.OTPRequest, error) {
	args := m.Called(uuid)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.OTPRequest), args.Error(1)
}

func (m *MockRedisClient) DeleteOTP(uuid string) error {
	args := m.Called(uuid)
	return args.Error(0)
}

func (m *MockRedisClient) UpdateRetryLimit(uuid string, otpData *models.OTPRequest) error {
	args := m.Called(uuid, otpData)
	return args.Error(0)
}

func (m *MockRedisClient) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockRedisClient) Ping() error {
	args := m.Called()
	return args.Error(0)
}

func TestSecurityHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{}
	cfg.Server.TLS.Enabled = false

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)

	// Apply security headers middleware
	r.Use(SecurityHeaders(cfg))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	c.Request = httptest.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, c.Request)

	// Check security headers
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "1; mode=block", w.Header().Get("X-XSS-Protection"))
	assert.Equal(t, "none", w.Header().Get("X-Permitted-Cross-Domain-Policies"))
	assert.Equal(t, "strict-origin-when-cross-origin", w.Header().Get("Referrer-Policy"))
	assert.Equal(t, "noopen", w.Header().Get("X-Download-Options"))
	assert.Equal(t, "off", w.Header().Get("X-DNS-Prefetch-Control"))
	assert.Equal(t, "no-store, max-age=0", w.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", w.Header().Get("Pragma"))
	assert.Equal(t, "", w.Header().Get("X-Powered-By"))
	assert.Equal(t, "", w.Header().Get("Server"))

	// Check CSP header
	csp := w.Header().Get("Content-Security-Policy")
	assert.Contains(t, csp, "default-src 'self'")
	assert.Contains(t, csp, "frame-ancestors 'none'")

	// Check Permissions-Policy header
	permissions := w.Header().Get("Permissions-Policy")
	assert.Contains(t, permissions, "camera 'none'")
	assert.Contains(t, permissions, "microphone 'none'")

	// Check Cross-Origin headers
	assert.Equal(t, "require-corp", w.Header().Get("Cross-Origin-Embedder-Policy"))
	assert.Equal(t, "same-origin", w.Header().Get("Cross-Origin-Opener-Policy"))
	assert.Equal(t, "same-origin", w.Header().Get("Cross-Origin-Resource-Policy"))
}

func TestSecurityHeadersWithTLS(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{}
	cfg.Server.TLS.Enabled = true

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)

	// Apply security headers middleware
	r.Use(SecurityHeaders(cfg))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	c.Request = httptest.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, c.Request)

	// Check HSTS header is present when TLS is enabled
	hsts := w.Header().Get("Strict-Transport-Security")
	assert.Equal(t, "max-age=31536000; includeSubDomains; preload", hsts)
}

func TestHealthCheckMiddleware_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockRedis := &MockRedisClient{}
	mockRedis.On("Ping").Return(nil)

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)

	// Apply health check middleware
	r.Use(HealthCheck(mockRedis))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	c.Request = httptest.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, c.Request)

	// Should proceed to next handler
	assert.Equal(t, http.StatusOK, w.Code)
	mockRedis.AssertExpectations(t)
}

func TestHealthCheckMiddleware_RedisDown(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockRedis := &MockRedisClient{}
	mockRedis.On("Ping").Return(assert.AnError)

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)

	// Apply health check middleware
	r.Use(HealthCheck(mockRedis))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	c.Request = httptest.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, c.Request)

	// Should return service unavailable
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	mockRedis.AssertExpectations(t)
}

func BenchmarkSecurityHeaders(b *testing.B) {
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{}
	cfg.Server.TLS.Enabled = false

	r := gin.New()
	r.Use(SecurityHeaders(cfg))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		r.ServeHTTP(w, req)
	}
}
