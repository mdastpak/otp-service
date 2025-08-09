package handlers

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"math/big"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"otp-service/internal/config"
	"otp-service/internal/metrics"
	"otp-service/internal/models"
	"otp-service/internal/redis"
)

var (
	uuidRegex = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	otpRegex  = regexp.MustCompile(`^[A-Za-z0-9]{1,10}$`)
)

type OTPHandler struct {
	redisClient redis.RedisInterface
	config      *config.Config
	logger      *logrus.Logger
	metrics     *metrics.Metrics
}

// NewOTPHandler creates a new OTP handler
func NewOTPHandler(redisClient redis.RedisInterface, cfg *config.Config, logger *logrus.Logger, m *metrics.Metrics) *OTPHandler {
	return &OTPHandler{
		redisClient: redisClient,
		config:      cfg,
		logger:      logger,
		metrics:     m,
	}
}

// validateUUID validates UUID format
func validateUUID(uuid string) bool {
	return uuidRegex.MatchString(uuid)
}

// validateOTP validates OTP format
func validateOTP(otp string) bool {
	return otpRegex.MatchString(otp)
}

// sanitizeInput removes potentially dangerous characters
func sanitizeInput(input string) string {
	return strings.TrimSpace(input)
}

// getExpirySeconds converts expiry string to seconds for default values
func (h *OTPHandler) getExpirySeconds() int {
	duration, err := time.ParseDuration(h.config.OTP.Expiry)
	if err != nil {
		return 60 // fallback default
	}
	return int(duration.Seconds())
}

// sendAPIResponse sends a standardized JSON API response
func (h *OTPHandler) sendAPIResponse(c *gin.Context, status int, message string, info interface{}) {
	c.JSON(status, models.APIResponse{
		Status:  status,
		Message: message,
		Info:    info,
	})
	h.logger.WithFields(logrus.Fields{
		"status":    status,
		"message":   message,
		"info":      info,
		"uuid":      c.GetString("uuid"),
		"client_ip": c.ClientIP(),
	}).Info("API response sent")
}

// generateOTP generates a random OTP code based on the given length and character set complexity
func generateOTP(length int, useAlphaNumeric bool) (string, error) {
	const numericChars = "0123456789"
	const alphaChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

	var charSet string
	charSet = numericChars
	if useAlphaNumeric {
		charSet += alphaChars
	}

	otpBytes := make([]byte, length)
	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charSet))))
		if err != nil {
			return "", err
		}
		otpBytes[i] = charSet[num.Int64()]
	}

	return string(otpBytes), nil
}

// GenerateOTP handles the POST request to generate an OTP
func (h *OTPHandler) GenerateOTP(c *gin.Context) {
	clientID := c.ClientIP()
	if h.redisClient.CheckRateLimit(clientID) {
		h.metrics.IncrementRateLimited()
		h.sendAPIResponse(c, http.StatusTooManyRequests, models.StatusRateLimitExceeded, nil)
		return
	}

	var otpRequest models.OTPRequest

	rawData, err := c.GetRawData()
	if err != nil {
		h.sendAPIResponse(c, http.StatusBadRequest, models.StatusRequestInvalid, nil)
		return
	}
	otpRequest.UserData = json.RawMessage(rawData)

	// Validate and set parameters using config defaults
	defaultTTL := strconv.Itoa(h.getExpirySeconds())
	ttl, err := strconv.Atoi(c.DefaultQuery("ttl", defaultTTL))
	if err != nil || ttl < 1 || ttl > 3600 {
		h.sendAPIResponse(c, http.StatusBadRequest, models.StatusTTLInvalid, nil)
		return
	}
	otpRequest.TTL = ttl
	otpRequest.TTLDuration = time.Duration(ttl) * time.Second

	defaultRetryLimit := strconv.Itoa(h.config.OTP.MaxAttempts)
	retryLimit, err := strconv.Atoi(c.DefaultQuery("retry_limit", defaultRetryLimit))
	if err != nil || retryLimit < 1 || retryLimit > 60 {
		h.sendAPIResponse(c, http.StatusBadRequest, models.StatusRetryInvalid, nil)
		return
	}
	otpRequest.RetryLimit = retryLimit

	defaultCodeLength := strconv.Itoa(h.config.OTP.Length)
	codeLength, err := strconv.Atoi(c.DefaultQuery("code_length", defaultCodeLength))
	if err != nil || codeLength < 1 || codeLength > 10 {
		h.sendAPIResponse(c, http.StatusBadRequest, models.StatusCodeInvalid, nil)
		return
	}
	otpRequest.CodeLength = codeLength

	otpRequest.StrictValidation = c.DefaultQuery("strict_validation", "false") == "true"
	otpRequest.UseAlphaNumeric = c.DefaultQuery("use_alpha_numeric", "false") == "true"

	// Generate OTP
	if otpRequest.OTP, err = generateOTP(otpRequest.CodeLength, otpRequest.UseAlphaNumeric); err != nil {
		h.sendAPIResponse(c, http.StatusInternalServerError, models.StatusOTPInvalid, nil)
		return
	}
	otpRequest.TTLDuration = time.Duration(otpRequest.TTL) * time.Second

	// Generate UUID and save OTP to Redis
	requestUUID := uuid.New().String()

	// Set UUID in context for later use in middleware
	c.Set("uuid", requestUUID)
	if err := h.redisClient.SaveOTP(requestUUID, otpRequest); err != nil {
		h.sendAPIResponse(c, http.StatusInternalServerError, models.StatusRedisUnavailable, nil)
		return
	}

	// Send response with generated UUID
	responseData := map[string]interface{}{
		"uuid": requestUUID,
	}

	if h.config.Server.Mode == "test" {
		responseData["otp"] = otpRequest.OTP
		responseData["test_mode"] = true
		responseData["debug_info"] = map[string]interface{}{
			"ttl":               otpRequest.TTL,
			"retry_limit":       otpRequest.RetryLimit,
			"code_length":       otpRequest.CodeLength,
			"use_alpha_numeric": otpRequest.UseAlphaNumeric,
			"strict_validation": otpRequest.StrictValidation,
			"client_ip":         c.ClientIP(),
			"user_agent":        c.Request.UserAgent(),
			"request_id":        c.GetString("uuid"),
		}
	}

	h.logger.WithFields(logrus.Fields{
		"uuid":      requestUUID,
		"client_ip": c.ClientIP(),
		"ttl":       otpRequest.TTL,
		"length":    otpRequest.CodeLength,
	}).Info("OTP generated successfully")

	h.metrics.IncrementOTPGenerated()
	h.sendAPIResponse(c, http.StatusOK, models.StatusOTPGenerated, responseData)
}

// VerifyOTP handles the GET request to verify an OTP
func (h *OTPHandler) VerifyOTP(c *gin.Context) {
	requestUUID := sanitizeInput(c.Query("uuid"))
	userInputOTP := sanitizeInput(c.Query("otp"))

	// Validate input
	if requestUUID == "" || userInputOTP == "" {
		h.sendAPIResponse(c, http.StatusBadRequest, models.StatusOTPMissing, nil)
		return
	}

	// Validate UUID and OTP format
	if !validateUUID(requestUUID) {
		h.sendAPIResponse(c, http.StatusBadRequest, models.StatusOTPMissing, nil)
		return
	}

	if !validateOTP(userInputOTP) {
		h.sendAPIResponse(c, http.StatusBadRequest, models.StatusOTPInvalid, nil)
		return
	}

	c.Set("uuid", requestUUID)

	// Get OTP data from Redis
	otpData, err := h.redisClient.GetOTP(requestUUID)
	if err != nil {
		h.metrics.IncrementOTPExpired()
		h.sendAPIResponse(c, http.StatusUnauthorized, models.StatusOTPExpired, nil)
		return
	}

	// Check if OTP is found
	if otpData.OTP == "" {
		h.sendAPIResponse(c, http.StatusUnauthorized, models.StatusOTPExpired, nil)
		return
	}

	// Check retry limit
	if otpData.RetryLimit <= 0 {
		if err := h.redisClient.DeleteOTP(requestUUID); err != nil {
			h.sendAPIResponse(c, http.StatusInternalServerError, models.StatusRedisUnavailable, nil)
			return
		}
		h.sendAPIResponse(c, http.StatusUnauthorized, models.StatusOTPLimitReached, nil)
		return
	}

	// Check OTP using constant-time comparison to prevent timing attacks
	// For case-insensitive comparison, normalize both strings first
	storedOTP := strings.ToUpper(otpData.OTP)
	inputOTP := strings.ToUpper(userInputOTP)

	// Use constant-time comparison
	if subtle.ConstantTimeCompare([]byte(storedOTP), []byte(inputOTP)) != 1 {
		h.metrics.IncrementOTPInvalid()
		if err := h.redisClient.UpdateRetryLimit(requestUUID, otpData); err != nil {
			h.sendAPIResponse(c, http.StatusInternalServerError, models.StatusOTPInvalid, nil)
			return
		}
		h.sendAPIResponse(c, http.StatusUnauthorized, models.StatusOTPInvalid, nil)
		return
	}

	// Full body validation, if strict validation is enabled
	if otpData.StrictValidation {
		var currentData map[string]interface{}
		if err := c.ShouldBindJSON(&currentData); err != nil {
			h.sendAPIResponse(c, http.StatusBadRequest, models.StatusRequestInvalid, nil)
			return
		}

		storedDataMap := make(map[string]interface{})
		if err := json.Unmarshal(otpData.UserData, &storedDataMap); err != nil {
			h.sendAPIResponse(c, http.StatusInternalServerError, models.StatusOTPInvalid, nil)
			return
		}

		// Validate specific fields instead of deep comparison
		storedDataJSON, err := json.Marshal(storedDataMap)
		if err != nil {
			h.sendAPIResponse(c, http.StatusInternalServerError, models.StatusOTPInvalid, nil)
			return
		}
		currentDataJSON, err := json.Marshal(currentData)
		if err != nil {
			h.sendAPIResponse(c, http.StatusInternalServerError, models.StatusOTPInvalid, nil)
			return
		}
		if string(storedDataJSON) != string(currentDataJSON) {
			if err := h.redisClient.UpdateRetryLimit(requestUUID, otpData); err != nil {
				h.sendAPIResponse(c, http.StatusInternalServerError, models.StatusOTPInvalid, nil)
				return
			}
			h.sendAPIResponse(c, http.StatusUnauthorized, models.StatusRequestMismatch, nil)
			return
		}
	}

	// OTP verified successfully, delete it from Redis
	if err := h.redisClient.DeleteOTP(requestUUID); err != nil {
		h.sendAPIResponse(c, http.StatusInternalServerError, models.StatusRedisUnavailable, nil)
		return
	}

	// Prepare response data
	var responseData interface{} = nil
	if h.config.Server.Mode == "test" {
		responseData = map[string]interface{}{
			"test_mode": true,
			"debug_info": map[string]interface{}{
				"verified_otp":      userInputOTP,
				"original_ttl":      otpData.TTL,
				"retry_limit":       otpData.RetryLimit,
				"client_ip":         c.ClientIP(),
				"user_agent":        c.Request.UserAgent(),
				"verification_time": time.Now().Format(time.RFC3339),
			},
		}
	}

	h.metrics.IncrementOTPVerified()
	h.sendAPIResponse(c, http.StatusOK, models.StatusOTPVerified, responseData)
}

// Health handles the health check endpoint
func (h *OTPHandler) Health(c *gin.Context) {
	responseData := map[string]interface{}{
		"redis_status": "OK",
		"config":       "***********",
		"server_mode":  h.config.Server.Mode,
	}
	// Show detailed info in test mode, minimal info in production/release modes
	if h.config.Server.Mode == "test" {
		responseData["test_mode"] = true
		responseData["debug_features"] = map[string]interface{}{
			"otp_visible_in_generation": true,
			"detailed_debug_info":       true,
			"request_tracking":          true,
		}
		// Show config details but not sensitive ones
		responseData["config_summary"] = map[string]interface{}{
			"redis_host":  h.config.Redis.Host,
			"redis_port":  h.config.Redis.Port,
			"server_host": h.config.Server.Host,
			"server_port": h.config.Server.Port,
			"hash_keys":   h.config.Config.HashKeys,
		}
		// Add additional debug information
		responseData["environment_info"] = map[string]interface{}{
			"server_mode":    h.config.Server.Mode,
			"cors_enabled":   true,
			"verbose_logs":   true,
			"health_checks":  "detailed",
		}
	}

	h.sendAPIResponse(c, http.StatusOK, models.StatusServiceHealth, responseData)
}

// Metrics handles the metrics endpoint
func (h *OTPHandler) Metrics(c *gin.Context) {
	stats := h.metrics.GetStats()
	h.sendAPIResponse(c, http.StatusOK, "METRICS", stats)
}
