package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"otp-service/internal/config"
	"otp-service/internal/handlers"
	"otp-service/internal/metrics"
	"otp-service/internal/middleware"
	"otp-service/internal/models"
	"otp-service/internal/redis"
)

// MockRedisClient for integration tests
type MockRedisClient struct {
	mock.Mock
	storage map[string]models.OTPRequest
}

var _ redis.RedisInterface = (*MockRedisClient)(nil)

func NewMockRedisClient() *MockRedisClient {
	return &MockRedisClient{
		storage: make(map[string]models.OTPRequest),
	}
}

func (m *MockRedisClient) CheckRateLimit(clientID string) bool {
	args := m.Called(clientID)
	return args.Bool(0)
}

func (m *MockRedisClient) SaveOTP(uuid string, otpData models.OTPRequest) error {
	args := m.Called(uuid, otpData)
	if args.Error(0) == nil {
		m.storage[uuid] = otpData
	}
	return args.Error(0)
}

func (m *MockRedisClient) GetOTP(uuid string) (*models.OTPRequest, error) {
	args := m.Called(uuid)
	if args.Error(1) != nil {
		return nil, args.Error(1)
	}
	if data, exists := m.storage[uuid]; exists {
		return &data, nil
	}
	return nil, args.Error(1)
}

func (m *MockRedisClient) DeleteOTP(uuid string) error {
	args := m.Called(uuid)
	if args.Error(0) == nil {
		delete(m.storage, uuid)
	}
	return args.Error(0)
}

func (m *MockRedisClient) UpdateRetryLimit(uuid string, otpData *models.OTPRequest) error {
	args := m.Called(uuid, otpData)
	if args.Error(0) == nil {
		m.storage[uuid] = *otpData
	}
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

func setupTestServer() (*gin.Engine, *MockRedisClient) {
	gin.SetMode(gin.TestMode)

	// Setup config
	cfg := &config.Config{}
	cfg.Server.Mode = "test"

	// Setup logger
	logger := config.SetupLogger("test")

	// Setup metrics
	m := metrics.NewMetrics(logger)

	// Setup mock Redis
	mockRedis := NewMockRedisClient()

	// Setup handlers
	otpHandler := handlers.NewOTPHandler(mockRedis, cfg, logger, m)

	// Setup router
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(middleware.SecurityHeaders(cfg))

	r.POST("/", otpHandler.GenerateOTP)
	r.GET("/", otpHandler.VerifyOTP)
	r.GET("/health", otpHandler.Health)
	r.GET("/metrics", otpHandler.Metrics)

	return r, mockRedis
}

func TestFullOTPFlow(t *testing.T) {
	router, mockRedis := setupTestServer()

	// Setup mock expectations
	mockRedis.On("CheckRateLimit", mock.AnythingOfType("string")).Return(false)
	mockRedis.On("SaveOTP", mock.AnythingOfType("string"), mock.AnythingOfType("models.OTPRequest")).Return(nil)
	mockRedis.On("GetOTP", mock.AnythingOfType("string")).Return(nil, nil) // Will use storage
	mockRedis.On("DeleteOTP", mock.AnythingOfType("string")).Return(nil)

	// Step 1: Generate OTP
	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("POST", "/?ttl=60&retry_limit=5&code_length=6", bytes.NewBuffer([]byte("{}")))
	req1.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w1, req1)

	assert.Equal(t, http.StatusOK, w1.Code)

	var generateResponse models.APIResponse
	err := json.Unmarshal(w1.Body.Bytes(), &generateResponse)
	assert.NoError(t, err)
	assert.Equal(t, models.StatusOTPGenerated, generateResponse.Message)

	responseInfo := generateResponse.Info.(map[string]interface{})
	uuid := responseInfo["uuid"].(string)
	otp := responseInfo["otp"].(string) // Available in test mode

	assert.NotEmpty(t, uuid)
	assert.NotEmpty(t, otp)
	assert.Len(t, otp, 6)

	// Step 2: Verify OTP with correct code
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/?uuid="+uuid+"&otp="+otp, nil)
	router.ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusOK, w2.Code)

	var verifyResponse models.APIResponse
	err = json.Unmarshal(w2.Body.Bytes(), &verifyResponse)
	assert.NoError(t, err)
	assert.Equal(t, models.StatusOTPVerified, verifyResponse.Message)

	mockRedis.AssertExpectations(t)
}

func TestRateLimiting(t *testing.T) {
	router, mockRedis := setupTestServer()

	// Setup mock expectations for rate limiting
	mockRedis.On("CheckRateLimit", mock.AnythingOfType("string")).Return(true)

	// Attempt to generate OTP when rate limited
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", bytes.NewBuffer([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusTooManyRequests, w.Code)

	var response models.APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, models.StatusRateLimitExceeded, response.Message)

	mockRedis.AssertExpectations(t)
}

func TestInvalidOTPVerification(t *testing.T) {
	router, mockRedis := setupTestServer()

	// Setup mock expectations
	mockRedis.On("CheckRateLimit", mock.AnythingOfType("string")).Return(false)
	mockRedis.On("SaveOTP", mock.AnythingOfType("string"), mock.AnythingOfType("models.OTPRequest")).Return(nil)
	mockRedis.On("GetOTP", mock.AnythingOfType("string")).Return(nil, nil) // Will use storage
	mockRedis.On("UpdateRetryLimit", mock.AnythingOfType("string"), mock.AnythingOfType("*models.OTPRequest")).Return(nil)

	// Step 1: Generate OTP
	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("POST", "/?ttl=60&retry_limit=5&code_length=6", bytes.NewBuffer([]byte("{}")))
	req1.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w1, req1)

	assert.Equal(t, http.StatusOK, w1.Code)

	var generateResponse models.APIResponse
	err := json.Unmarshal(w1.Body.Bytes(), &generateResponse)
	assert.NoError(t, err)

	responseInfo := generateResponse.Info.(map[string]interface{})
	uuid := responseInfo["uuid"].(string)

	// Step 2: Verify OTP with wrong code
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/?uuid="+uuid+"&otp=wrong123", nil)
	router.ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusUnauthorized, w2.Code)

	var verifyResponse models.APIResponse
	err = json.Unmarshal(w2.Body.Bytes(), &verifyResponse)
	assert.NoError(t, err)
	assert.Equal(t, models.StatusOTPInvalid, verifyResponse.Message)

	mockRedis.AssertExpectations(t)
}

func TestHealthEndpoint(t *testing.T) {
	router, _ := setupTestServer()

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/health", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response models.APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, models.StatusServiceHealth, response.Message)

	responseInfo := response.Info.(map[string]interface{})
	assert.Equal(t, "OK", responseInfo["redis_status"])
}

func TestMetricsEndpoint(t *testing.T) {
	router, mockRedis := setupTestServer()

	// Setup mock expectations
	mockRedis.On("CheckRateLimit", mock.AnythingOfType("string")).Return(false)
	mockRedis.On("SaveOTP", mock.AnythingOfType("string"), mock.AnythingOfType("models.OTPRequest")).Return(nil)

	// Generate an OTP first to have some metrics
	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("POST", "/", bytes.NewBuffer([]byte("{}")))
	req1.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w1, req1)

	// Now check metrics
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/metrics", nil)
	router.ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusOK, w2.Code)

	var response models.APIResponse
	err := json.Unmarshal(w2.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "METRICS", response.Message)

	responseInfo := response.Info.(map[string]interface{})
	assert.Contains(t, responseInfo, "otp_generated")
	assert.Contains(t, responseInfo, "total_requests")
	assert.Contains(t, responseInfo, "uptime_seconds")

	// Should have at least 1 OTP generated
	assert.GreaterOrEqual(t, int(responseInfo["otp_generated"].(float64)), 1)

	mockRedis.AssertExpectations(t)
}

func TestSecurityHeaders(t *testing.T) {
	router, _ := setupTestServer()

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/health", nil)
	router.ServeHTTP(w, req)

	// Check that security headers are present
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "1; mode=block", w.Header().Get("X-XSS-Protection"))
	assert.Contains(t, w.Header().Get("Content-Security-Policy"), "default-src 'self'")
}

func TestInvalidParameters(t *testing.T) {
	router, mockRedis := setupTestServer()

	mockRedis.On("CheckRateLimit", mock.AnythingOfType("string")).Return(false)

	tests := []struct {
		name           string
		params         string
		expectedStatus int
		expectedMsg    string
	}{
		{
			name:           "Invalid TTL - too high",
			params:         "?ttl=5000",
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    models.StatusTTLInvalid,
		},
		{
			name:           "Invalid retry limit - too high",
			params:         "?retry_limit=100",
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    models.StatusRetryInvalid,
		},
		{
			name:           "Invalid code length - too long",
			params:         "?code_length=20",
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    models.StatusCodeInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/"+tt.params, bytes.NewBuffer([]byte("{}")))
			req.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var response models.APIResponse
			err := json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedMsg, response.Message)
		})
	}

	mockRedis.AssertExpectations(t)
}

func BenchmarkOTPGeneration(b *testing.B) {
	router, mockRedis := setupTestServer()

	mockRedis.On("CheckRateLimit", mock.AnythingOfType("string")).Return(false)
	mockRedis.On("SaveOTP", mock.AnythingOfType("string"), mock.AnythingOfType("models.OTPRequest")).Return(nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/", bytes.NewBuffer([]byte("{}")))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)
	}
}
