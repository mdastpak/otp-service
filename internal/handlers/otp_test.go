package handlers

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
	"otp-service/internal/metrics"
	"otp-service/internal/models"
	"otp-service/internal/redis"
)

// MockRedisClient is a mock implementation of the Redis client
type MockRedisClient struct {
	mock.Mock
}

// Ensure MockRedisClient implements RedisInterface
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

func setupTestHandler() (*OTPHandler, *MockRedisClient) {
	mockRedis := &MockRedisClient{}
	cfg := &config.Config{}
	cfg.Server.Mode = "test"
	logger := config.SetupLogger("test")
	metrics := metrics.NewMetrics(logger)

	handler := NewOTPHandler(mockRedis, cfg, logger, metrics)
	return handler, mockRedis
}

func TestGenerateOTP_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, mockRedis := setupTestHandler()

	// Setup expectations
	mockRedis.On("CheckRateLimit", mock.AnythingOfType("string")).Return(false)
	mockRedis.On("SaveOTP", mock.AnythingOfType("string"), mock.AnythingOfType("models.OTPRequest")).Return(nil)

	// Create request
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/?ttl=60&retry_limit=5&code_length=6", bytes.NewBuffer([]byte("{}")))
	c.Request.Header.Set("Content-Type", "application/json")

	// Execute
	handler.GenerateOTP(c)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response models.APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, models.StatusOTPGenerated, response.Message)
	assert.NotNil(t, response.Info)

	mockRedis.AssertExpectations(t)
}

func TestGenerateOTP_RateLimited(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, mockRedis := setupTestHandler()

	// Setup expectations
	mockRedis.On("CheckRateLimit", mock.AnythingOfType("string")).Return(true)

	// Create request
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/", bytes.NewBuffer([]byte("{}")))

	// Execute
	handler.GenerateOTP(c)

	// Assertions
	assert.Equal(t, http.StatusTooManyRequests, w.Code)

	var response models.APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, models.StatusRateLimitExceeded, response.Message)

	mockRedis.AssertExpectations(t)
}

func TestGenerateOTP_InvalidTTL(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, mockRedis := setupTestHandler()

	// Setup expectations
	mockRedis.On("CheckRateLimit", mock.AnythingOfType("string")).Return(false)

	// Create request with invalid TTL
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/?ttl=5000", bytes.NewBuffer([]byte("{}")))

	// Execute
	handler.GenerateOTP(c)

	// Assertions
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response models.APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, models.StatusTTLInvalid, response.Message)

	mockRedis.AssertExpectations(t)
}

func TestVerifyOTP_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, mockRedis := setupTestHandler()

	// Setup expectations
	otpData := &models.OTPRequest{
		OTP:              "123456",
		RetryLimit:       5,
		StrictValidation: false,
	}
	testUUID := "550e8400-e29b-41d4-a716-446655440000"
	mockRedis.On("GetOTP", testUUID).Return(otpData, nil)
	mockRedis.On("DeleteOTP", testUUID).Return(nil)

	// Create request
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/?uuid="+testUUID+"&otp=123456", nil)
	req.Header.Set("X-Real-IP", "192.0.2.1")
	c.Request = req

	// Execute
	handler.VerifyOTP(c)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response models.APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, models.StatusOTPVerified, response.Message)

	mockRedis.AssertExpectations(t)
}

func TestVerifyOTP_InvalidOTP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, mockRedis := setupTestHandler()

	// Setup expectations
	otpData := &models.OTPRequest{
		OTP:              "123456",
		RetryLimit:       5,
		StrictValidation: false,
	}
	testUUID := "550e8400-e29b-41d4-a716-446655440000"
	mockRedis.On("GetOTP", testUUID).Return(otpData, nil)
	mockRedis.On("UpdateRetryLimit", testUUID, otpData).Return(nil)

	// Create request with wrong OTP
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/?uuid="+testUUID+"&otp=654321", nil)
	req.Header.Set("X-Real-IP", "192.0.2.1")
	c.Request = req

	// Execute
	handler.VerifyOTP(c)

	// Assertions
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response models.APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, models.StatusOTPInvalid, response.Message)

	mockRedis.AssertExpectations(t)
}

func TestVerifyOTP_MissingParameters(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, _ := setupTestHandler()

	// Create request without parameters
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/", nil)

	// Execute
	handler.VerifyOTP(c)

	// Assertions
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response models.APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, models.StatusOTPMissing, response.Message)
}

func TestHealth_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, _ := setupTestHandler()

	// Create request
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/health", nil)

	// Execute
	handler.Health(c)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response models.APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, models.StatusServiceHealth, response.Message)
}

// Benchmark tests
func BenchmarkGenerateOTP(b *testing.B) {
	gin.SetMode(gin.TestMode)
	handler, mockRedis := setupTestHandler()

	mockRedis.On("CheckRateLimit", mock.AnythingOfType("string")).Return(false)
	mockRedis.On("SaveOTP", mock.AnythingOfType("string"), mock.AnythingOfType("models.OTPRequest")).Return(nil)

	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("POST", "/?ttl=60", bytes.NewBuffer([]byte("{}")))
		handler.GenerateOTP(c)
	}
}

func TestValidateUUID(t *testing.T) {
	tests := []struct {
		name     string
		uuid     string
		expected bool
	}{
		{
			name:     "Valid UUID",
			uuid:     "123e4567-e89b-12d3-a456-426614174000",
			expected: true,
		},
		{
			name:     "Invalid UUID - too short",
			uuid:     "123e4567-e89b-12d3-a456",
			expected: false,
		},
		{
			name:     "Invalid UUID - wrong format",
			uuid:     "not-a-uuid",
			expected: false,
		},
		{
			name:     "Empty string",
			uuid:     "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validateUUID(tt.uuid)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateOTP(t *testing.T) {
	tests := []struct {
		name     string
		otp      string
		expected bool
	}{
		{
			name:     "Valid numeric OTP",
			otp:      "123456",
			expected: true,
		},
		{
			name:     "Valid alphanumeric OTP",
			otp:      "A1B2C3",
			expected: true,
		},
		{
			name:     "Too long OTP",
			otp:      "12345678901",
			expected: false,
		},
		{
			name:     "Invalid characters",
			otp:      "123!@#",
			expected: false,
		},
		{
			name:     "Empty string",
			otp:      "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validateOTP(tt.otp)
			assert.Equal(t, tt.expected, result)
		})
	}
}
