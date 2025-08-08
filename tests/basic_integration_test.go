package tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"otp-service/internal/config"
	"otp-service/internal/handlers"
	"otp-service/internal/metrics"
	"otp-service/internal/models"
	"otp-service/internal/redis"
)

// setupTestEnvironment creates a test router and handler
func setupTestEnvironment(t *testing.T, mode string) (*gin.Engine, *handlers.OTPHandler, *redis.Client) {
	gin.SetMode(gin.TestMode)
	
	// Configure test environment
	cfg := &config.Config{}
	cfg.Server.Mode = mode
	cfg.Redis.Host = getEnvOrDefault("REDIS_HOST", "localhost")
	cfg.Redis.Port = getEnvOrDefault("REDIS_PORT", "6379")
	cfg.Redis.Indices = "0-5"
	cfg.Redis.KeyPrefix = "otp:test:"
	cfg.Redis.Timeout = 5
	cfg.Config.HashKeys = true
	
	// Initialize components
	logger := config.SetupLogger(mode)
	metrics := metrics.NewMetrics(logger)
	
	// Initialize Redis client
	redisClient, err := redis.NewClient(cfg, logger)
	if err != nil {
		t.Skip("Redis not available for integration tests")
		return nil, nil, nil
	}
	
	handler := handlers.NewOTPHandler(redisClient, cfg, logger, metrics)
	
	// Setup router with appropriate middleware
	router := gin.New()
	router.Use(gin.Recovery())
	
	if mode == "test" || mode == "debug" {
		// Test mode: Permissive CORS
		router.Use(func(c *gin.Context) {
			c.Header("Access-Control-Allow-Origin", "*")
			c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "*")
			
			if c.Request.Method == "OPTIONS" {
				c.AbortWithStatus(http.StatusNoContent)
				return
			}
			c.Next()
		})
	} else {
		// Production mode: Strict CORS and security headers
		router.Use(func(c *gin.Context) {
			c.Header("Access-Control-Allow-Origin", "https://yourapp.com")
			c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization")
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			c.Header("X-Frame-Options", "DENY")
			c.Header("X-Content-Type-Options", "nosniff")
			
			if c.Request.Method == "OPTIONS" {
				c.AbortWithStatus(http.StatusNoContent)
				return
			}
			c.Next()
		})
	}
	
	// Register routes
	router.POST("/", handler.GenerateOTP)
	router.GET("/", handler.VerifyOTP)
	router.GET("/health", handler.Health)
	
	return router, handler, redisClient
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// TestBasicOTPFlow tests the complete OTP generation and verification flow
func TestBasicOTPFlow(t *testing.T) {
	router, _, redisClient := setupTestEnvironment(t, "test")
	if router == nil {
		return // Skipped due to Redis unavailability
	}
	defer redisClient.Close()
	
	// Step 1: Generate OTP
	w1 := httptest.NewRecorder()
	req1, _ := http.NewRequest("POST", "/?ttl=300&retry_limit=5&code_length=6", bytes.NewBuffer([]byte("{}")))
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("X-Real-IP", "192.168.1.1")
	
	router.ServeHTTP(w1, req1)
	
	assert.Equal(t, http.StatusOK, w1.Code)
	
	var genResponse models.APIResponse
	err := json.Unmarshal(w1.Body.Bytes(), &genResponse)
	assert.NoError(t, err)
	assert.Equal(t, models.StatusOTPGenerated, genResponse.Message)
	assert.NotNil(t, genResponse.Info)
	
	// Extract UUID and OTP
	info, ok := genResponse.Info.(map[string]interface{})
	assert.True(t, ok)
	uuid := info["uuid"].(string)
	otp := info["otp"].(string)
	assert.NotEmpty(t, uuid)
	assert.NotEmpty(t, otp)
	
	// Step 2: Verify OTP
	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest("GET", fmt.Sprintf("/?uuid=%s&otp=%s", uuid, otp), nil)
	req2.Header.Set("X-Real-IP", "192.168.1.1")
	
	router.ServeHTTP(w2, req2)
	
	assert.Equal(t, http.StatusOK, w2.Code)
	
	var verifyResponse models.APIResponse
	err = json.Unmarshal(w2.Body.Bytes(), &verifyResponse)
	assert.NoError(t, err)
	assert.Equal(t, models.StatusOTPVerified, verifyResponse.Message)
}

// TestInvalidOTP tests OTP verification with wrong OTP
func TestInvalidOTP(t *testing.T) {
	router, _, redisClient := setupTestEnvironment(t, "test")
	if router == nil {
		return
	}
	defer redisClient.Close()
	
	// Generate OTP
	w1 := httptest.NewRecorder()
	req1, _ := http.NewRequest("POST", "/?ttl=300&retry_limit=5&code_length=6", bytes.NewBuffer([]byte("{}")))
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("X-Real-IP", "192.168.1.2")
	
	router.ServeHTTP(w1, req1)
	assert.Equal(t, http.StatusOK, w1.Code)
	
	var genResponse models.APIResponse
	err := json.Unmarshal(w1.Body.Bytes(), &genResponse)
	assert.NoError(t, err)
	
	info, ok := genResponse.Info.(map[string]interface{})
	assert.True(t, ok)
	uuid := info["uuid"].(string)
	
	// Verify with wrong OTP
	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest("GET", fmt.Sprintf("/?uuid=%s&otp=999999", uuid), nil)
	req2.Header.Set("X-Real-IP", "192.168.1.2")
	
	router.ServeHTTP(w2, req2)
	
	assert.Equal(t, http.StatusUnauthorized, w2.Code)
	
	var verifyResponse models.APIResponse
	err = json.Unmarshal(w2.Body.Bytes(), &verifyResponse)
	assert.NoError(t, err)
	assert.Equal(t, models.StatusOTPInvalid, verifyResponse.Message)
}

// TestExpiredOTP tests OTP verification after expiry
func TestExpiredOTP(t *testing.T) {
	router, _, redisClient := setupTestEnvironment(t, "test")
	if router == nil {
		return
	}
	defer redisClient.Close()
	
	// Generate OTP with short TTL
	w1 := httptest.NewRecorder()
	req1, _ := http.NewRequest("POST", "/?ttl=1&retry_limit=5&code_length=6", bytes.NewBuffer([]byte("{}")))
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("X-Real-IP", "192.168.1.3")
	
	router.ServeHTTP(w1, req1)
	assert.Equal(t, http.StatusOK, w1.Code)
	
	var genResponse models.APIResponse
	err := json.Unmarshal(w1.Body.Bytes(), &genResponse)
	assert.NoError(t, err)
	
	info, ok := genResponse.Info.(map[string]interface{})
	assert.True(t, ok)
	uuid := info["uuid"].(string)
	otp := info["otp"].(string)
	
	// Wait for expiry
	time.Sleep(2 * time.Second)
	
	// Try to verify expired OTP
	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest("GET", fmt.Sprintf("/?uuid=%s&otp=%s", uuid, otp), nil)
	req2.Header.Set("X-Real-IP", "192.168.1.3")
	
	router.ServeHTTP(w2, req2)
	
	assert.Equal(t, http.StatusUnauthorized, w2.Code)
	
	var verifyResponse models.APIResponse
	err = json.Unmarshal(w2.Body.Bytes(), &verifyResponse)
	assert.NoError(t, err)
	assert.Equal(t, models.StatusOTPExpired, verifyResponse.Message)
}

// TestCORSHeaders tests CORS functionality
func TestCORSHeaders(t *testing.T) {
	router, _, redisClient := setupTestEnvironment(t, "test")
	if router == nil {
		return
	}
	defer redisClient.Close()
	
	// Test OPTIONS preflight request
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("OPTIONS", "/", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Contains(t, w.Header().Get("Access-Control-Allow-Methods"), "GET")
	assert.Contains(t, w.Header().Get("Access-Control-Allow-Methods"), "POST")
}

// TestHealthEndpoint tests the health check endpoint
func TestHealthEndpoint(t *testing.T) {
	router, _, redisClient := setupTestEnvironment(t, "test")
	if router == nil {
		return
	}
	defer redisClient.Close()
	
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/health", nil)
	
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	
	var response models.APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, models.StatusServiceHealth, response.Message)
}

// TestInvalidParameters tests parameter validation
func TestInvalidParameters(t *testing.T) {
	router, _, redisClient := setupTestEnvironment(t, "test")
	if router == nil {
		return
	}
	defer redisClient.Close()
	
	testCases := []struct {
		name           string
		url            string
		expectedStatus int
	}{
		{"Invalid TTL too high", "/?ttl=5000&retry_limit=5&code_length=6", http.StatusBadRequest},
		{"Invalid TTL too low", "/?ttl=0&retry_limit=5&code_length=6", http.StatusBadRequest},
		{"Invalid retry limit", "/?ttl=300&retry_limit=0&code_length=6", http.StatusBadRequest},
		{"Invalid code length", "/?ttl=300&retry_limit=5&code_length=20", http.StatusBadRequest},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("POST", tc.url, bytes.NewBuffer([]byte("{}")))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Real-IP", "192.168.1.4")
			
			router.ServeHTTP(w, req)
			
			assert.Equal(t, tc.expectedStatus, w.Code)
		})
	}
}

// TestMissingVerificationParameters tests missing parameter handling
func TestMissingVerificationParameters(t *testing.T) {
	router, _, redisClient := setupTestEnvironment(t, "test")
	if router == nil {
		return
	}
	defer redisClient.Close()
	
	testCases := []struct {
		name string
		url  string
	}{
		{"Missing UUID", "/?otp=123456"},
		{"Missing OTP", "/?uuid=550e8400-e29b-41d4-a716-446655440000"},
		{"Missing both", "/"},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", tc.url, nil)
			req.Header.Set("X-Real-IP", "192.168.1.5")
			
			router.ServeHTTP(w, req)
			
			assert.Equal(t, http.StatusBadRequest, w.Code)
			
			var response models.APIResponse
			err := json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, models.StatusOTPMissing, response.Message)
		})
	}
}

// TestProductionModeHeaders tests production security headers
func TestProductionModeHeaders(t *testing.T) {
	router, _, redisClient := setupTestEnvironment(t, "release")
	if router == nil {
		return
	}
	defer redisClient.Close()
	
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/health", nil)
	
	router.ServeHTTP(w, req)
	
	// Check security headers
	assert.NotEmpty(t, w.Header().Get("Strict-Transport-Security"))
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
}

// TestSecurityInputs tests basic security input validation
func TestSecurityInputs(t *testing.T) {
	router, _, redisClient := setupTestEnvironment(t, "release")
	if router == nil {
		return
	}
	defer redisClient.Close()
	
	maliciousInputs := []string{
		"'; DROP TABLE users; --",
		"<script>alert('XSS')</script>",
		"javascript:alert('XSS')",
		"../../etc/passwd",
		"%00%01%02%03",
	}
	
	for _, input := range maliciousInputs {
		t.Run(fmt.Sprintf("Malicious input: %s", input), func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", fmt.Sprintf("/?uuid=550e8400-e29b-41d4-a716-446655440000&otp=%s", input), nil)
			req.Header.Set("X-Real-IP", "192.168.1.6")
			
			router.ServeHTTP(w, req)
			
			// Should not cause server error
			assert.NotEqual(t, http.StatusInternalServerError, w.Code)
			
			// Response should be safe JSON
			contentType := w.Header().Get("Content-Type")
			assert.Contains(t, contentType, "application/json")
		})
	}
}