package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var (
	logger      = logrus.New()
	cfg         Config
	ctx         = context.Background()
	redisClient *redis.Client
)

// Config structure to hold server, redis, and general configurations
type Config struct {
	Redis struct {
		Host      string `mapstructure:"host"`
		Port      string `mapstructure:"port"`
		Password  string `mapstructure:"password"`
		Indices   string `mapstructure:"indices"`
		KeyPrefix string `mapstructure:"key_prefix"`
		Timeout   int    `mapstructure:"timeout"`
	} `mapstructure:"redis"`
	Server struct {
		Host    string `mapstructure:"host"`
		Port    string `mapstructure:"port"`
		Mode    string `mapstructure:"mode"`
		Timeout struct {
			Read       int `mapstructure:"read"`
			Write      int `mapstructure:"write"`
			Idle       int `mapstructure:"idle"`
			ReadHeader int `mapstructure:"read_header"`
		}
		TLS struct {
			Enabled     bool   `mapstructure:"enabled"`
			CertFile    string `mapstructure:"cert_file"`
			KeyFile     string `mapstructure:"key_file"`
			ClientCerts string `mapstructure:"client_certs"`
		} `mapstructure:"tls"`
	} `mapstructure:"server"`
	Config struct {
		HashKeys bool `mapstructure:"hash_keys"`
	} `mapstructure:"config"`
}

const (
	StatusOTPGenerated      = "OTP_GENERATED"
	StatusOTPExpired        = "OTP_EXPIRED"
	StatusOTPInvalid        = "OTP_INVALID"
	StatusOTPVerified       = "OTP_VERIFIED"
	StatusOTPMissing        = "OTP_MISSING"
	StatusOTPLimitReached   = "OTP_ATTEMPTS"
	StatusRequestMismatch   = "REQUEST_BODY_MISMATCH"
	StatusTTLInvalid        = "TTL_INVALID"
	StatusRetryInvalid      = "RETRY_INVALID"
	StatusCodeInvalid       = "CODE_LENGTH_INVALID"
	StatusRequestInvalid    = "REQUEST_BODY_INVALID"
	StatusServiceHealth     = "SERVICE_HEALTH"
	StatusRedisUnavailable  = "REDIS_UNAVAILABLE"
	StatusRateLimitExceeded = "RATE_LIMIT_EXCEEDED"
)

var (
	uuidRegex = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	otpRegex  = regexp.MustCompile(`^[A-Za-z0-9]{1,10}$`)
)

// loadConfig reads the configuration from the config file and environment variables
func loadConfig() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")

	if err := viper.ReadInConfig(); err != nil {
		handleFatalError("Error reading config file", err)
	}
	viper.AutomaticEnv()

	// Bind environment variables to specific keys in the config
	viper.BindEnv("redis.host", "REDIS_HOST")
	viper.BindEnv("redis.port", "REDIS_PORT")
	viper.BindEnv("redis.password", "REDIS_PASSWORD")
	viper.BindEnv("redis.indices", "REDIS_INDICES")
	viper.BindEnv("redis.key_prefix", "REDIS_KEY_PREFIX")
	viper.BindEnv("redis.timeout", "REDIS_TIMEOUT")
	viper.BindEnv("server.host", "SERVER_HOST")
	viper.BindEnv("server.port", "SERVER_PORT")
	viper.BindEnv("server.mode", "SERVER_MODE")
	viper.BindEnv("cfg.hash_keys", "HASH_KEYS")

	// Unmarshal configuration into Config struct
	if err := viper.Unmarshal(&cfg); err != nil {
		handleFatalError("Unable to decode into struct", err)
	}
}

// initRedis initializes the Redis client and checks the connection.
func initRedis() {
	redisClient = redis.NewClient(&redis.Options{
		Addr:         fmt.Sprintf("%s:%s", cfg.Redis.Host, cfg.Redis.Port),
		Password:     cfg.Redis.Password,
		ReadTimeout:  time.Duration(cfg.Redis.Timeout) * time.Second,
		WriteTimeout: time.Duration(cfg.Redis.Timeout) * time.Second,
	})

	// Test Redis connection with a context timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Redis.Timeout)*time.Second)
	defer cancel()

	_, err := redisClient.Ping(ctx).Result()
	if err != nil {
		handleFatalError("Failed to connect to Redis", err)
	}
	logger.Info("Connected to Redis successfully")
}

func init() {
	// Skip initialization during tests
	for _, arg := range os.Args {
		if strings.Contains(arg, "test") {
			return
		}
	}

	// Initialize logger
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetLevel(logrus.InfoLevel)

	// Load configuration
	loadConfig()

	// Initialize Redis client
	initRedis()

	logger.SetLevel(logrus.InfoLevel)

	if cfg.Server.Mode != "release" {
		logger.SetLevel(logrus.TraceLevel)
	}
}

// handleFatalError logs a fatal error and terminates the program
func handleFatalError(message string, err error) {
	logger.Fatalf("%s: %v", message, err)
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

// APIResponse defines the standard structure for all API responses
type APIResponse struct {
	Status  int         `json:"status"`
	Message string      `json:"message"`
	Info    interface{} `json:"info,omitempty"`
}

// OTPRequest structure for storing OTP-related info
type OTPRequest struct {
	OTP              string          `json:"otp"`
	TTL              int             `json:"ttl"`
	RetryLimit       int             `json:"retry_limit"`
	UseAlphaNumeric  bool            `json:"use_alpha_numeric"`
	TTLDuration      time.Duration   `json:"ttl_duration"`
	CodeLength       int             `json:"code_length"`
	StrictValidation bool            `json:"strict_validation"`
	UserData         json.RawMessage `json:"user_data,omitempty"`
}

// sendAPIResponse sends a standardized JSON API response
func sendAPIResponse(c *gin.Context, status int, message string, info interface{}) {
	c.JSON(status, APIResponse{
		Status:  status,
		Message: message,
		Info:    info,
	})
	logger.WithFields(logrus.Fields{
		"status":    status,
		"message":   message,
		"info":      info,
		"uuid":      c.GetString("uuid"),
		"client_ip": c.ClientIP(),
	}).Info("API response sent")
}

// isRateLimited checks if a client is being rate limited by checking Redis for recent requests
func isRateLimited(clientID string) bool {
	redisKey := fmt.Sprintf("rate_limit:%s", clientID)
	limiterCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	// Use Redis counter for more accurate rate limiting
	count, err := redisClient.Incr(limiterCtx, redisKey).Result()
	if err != nil {
		logger.Errorf("Rate limit check failed: %v", err)
		return false
	}

	// Set expiration only for the first request
	if count == 1 {
		_ = redisClient.Expire(limiterCtx, redisKey, time.Minute).Err()
	}

	// Allow up to 10 requests per minute
	return count > 10
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

// generateRedisKey generates a Redis key using SHA-256 hash of the request UUID
func generateRedisKey(requestUUID string) string {
	hash := sha256.Sum256([]byte(requestUUID))
	return hex.EncodeToString(hash[:])
}

// getRedisKey generates the final Redis key using the configuration settings
func getRedisKey(uuid string) string {
	key := uuid
	if cfg.Config.HashKeys {
		key = generateRedisKey(uuid)
	}
	if cfg.Redis.KeyPrefix != "" {
		key = fmt.Sprintf("%s:%s", cfg.Redis.KeyPrefix, key)
	}
	return key
}

// getShardIndex determines the appropriate Redis shard index based on UUID
func getShardIndex(uuid string) int {
	rangeParts := strings.Split(cfg.Redis.Indices, "-")
	if cfg.Redis.Indices == "0" {
		return 0 // Directly return shard 0 if the index is set to 0
	}
	if len(rangeParts) == 1 {
		index, err := strconv.Atoi(rangeParts[0])
		if err != nil {
			handleFatalError("Invalid Redis Indices configuration", err)
		}
		if index == 0 {
			return 0 // Avoid division by zero
		}
		return int(sha256.Sum256([]byte(uuid))[0]) % index
	} else if len(rangeParts) == 2 {
		start, err := strconv.Atoi(rangeParts[0])
		if err != nil {
			handleFatalError("Invalid Redis Indices configuration", err)
		}
		end, err := strconv.Atoi(rangeParts[1])
		if err != nil {
			handleFatalError("Invalid Redis Indices configuration", err)
		}
		shardRange := end - start + 1
		if shardRange == 0 {
			handleFatalError("Invalid Redis Indices configuration: range results in zero", nil)
		}
		return int(sha256.Sum256([]byte(uuid))[0]) % shardRange
	} else {
		handleFatalError("Invalid Redis Indices format. Use a single number or a range (e.g., '0-2')", nil)
	}
	return 0
}

// saveOTPToRedis saves the OTP data to Redis under the appropriate shard
func saveOTPToRedis(uuid string, otpData OTPRequest) error {
	// Save the raw body (UserData) to Redis in all cases
	if otpData.UserData == nil {
		rawData, err := json.Marshal(otpData)
		if err != nil {
			return fmt.Errorf("error marshaling OTP data: %v", err)
		}
		otpData.UserData = json.RawMessage(rawData)
	}
	key := getRedisKey(uuid)

	otpJSON, err := json.Marshal(otpData)
	if err != nil {
		return fmt.Errorf("error marshaling OTP data: %v", err)
	}

	saveCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	shardIndex := getShardIndex(uuid)
	if err := redisClient.Do(saveCtx, "SELECT", shardIndex).Err(); err != nil {
		return fmt.Errorf("error selecting Redis index: %v", err)
	}

	if err := redisClient.Set(saveCtx, key, otpJSON, otpData.TTLDuration).Err(); err != nil {
		return fmt.Errorf("error saving OTP to Redis: %v", err)
	}
	return nil
}

// getOTPFromRedis retrieves the OTP data from Redis using the appropriate shard
func getOTPFromRedis(uuid string) (*OTPRequest, error) {
	key := getRedisKey(uuid)

	retrieveCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	shardIndex := getShardIndex(uuid)
	if err := redisClient.Do(retrieveCtx, "SELECT", shardIndex).Err(); err != nil {
		return nil, fmt.Errorf("error selecting Redis index: %v", err)
	}

	result, err := redisClient.Get(retrieveCtx, key).Result()
	if err == redis.Nil {
		return nil, fmt.Errorf(StatusOTPExpired)
	} else if err != nil {
		return nil, fmt.Errorf("error retrieving OTP from Redis: %v", err)
	}

	var otpData OTPRequest
	if err := json.Unmarshal([]byte(result), &otpData); err != nil {
		return nil, fmt.Errorf("error unmarshaling OTP data: %v", err)
	}
	return &otpData, nil
}

// delOTPFromRedis deletes the OTP data from Redis under the appropriate shard
func delOTPFromRedis(uuid string) error {
	key := getRedisKey(uuid)

	deleteCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	shardIndex := getShardIndex(uuid)
	if err := redisClient.Do(deleteCtx, "SELECT", shardIndex).Err(); err != nil {
		return fmt.Errorf("error selecting Redis index: %v", err)
	}

	if err := redisClient.Del(deleteCtx, key).Err(); err != nil {
		return fmt.Errorf("error deleting OTP from Redis: %v", err)
	}
	return nil
}


// generateOTPHandler handles the POST request to generate an OTP
func generateOTPHandler(c *gin.Context) {
	clientID := c.ClientIP()
	if isRateLimited(clientID) {
		sendAPIResponse(c, http.StatusTooManyRequests, StatusRateLimitExceeded, nil)
		return
	}

	var otpRequest OTPRequest

	rawData, err := c.GetRawData()
	if err != nil {
		sendAPIResponse(c, http.StatusBadRequest, StatusRequestInvalid, nil)
		return
	}
	otpRequest.UserData = json.RawMessage(rawData)

	// Validate and set parameters
	ttl, err := strconv.Atoi(c.DefaultQuery("ttl", "60"))
	if err != nil || ttl < 1 || ttl > 3600 {
		sendAPIResponse(c, http.StatusBadRequest, StatusTTLInvalid, nil)
		return
	}
	otpRequest.TTL = ttl
	otpRequest.TTLDuration = time.Duration(ttl) * time.Second

	retryLimit, err := strconv.Atoi(c.DefaultQuery("retry_limit", "5"))
	if err != nil || retryLimit < 1 || retryLimit > 60 {
		sendAPIResponse(c, http.StatusBadRequest, StatusRetryInvalid, nil)
		return
	}
	otpRequest.RetryLimit = retryLimit

	codeLength, err := strconv.Atoi(c.DefaultQuery("code_length", "6"))
	if err != nil || codeLength < 1 || codeLength > 10 {
		sendAPIResponse(c, http.StatusBadRequest, StatusCodeInvalid, nil)
		return
	}
	otpRequest.CodeLength = codeLength

	otpRequest.StrictValidation = c.DefaultQuery("strict_validation", "false") == "true"
	otpRequest.UseAlphaNumeric = c.DefaultQuery("use_alpha_numeric", "false") == "true"

	// Generate OTP
	if otpRequest.OTP, err = generateOTP(otpRequest.CodeLength, otpRequest.UseAlphaNumeric); err != nil {
		sendAPIResponse(c, http.StatusInternalServerError, StatusOTPInvalid, nil)
		return
	}
	otpRequest.TTLDuration = time.Duration(otpRequest.TTL) * time.Second

	// Generate UUID and save OTP to Redis
	requestUUID := uuid.New().String()

	// Set UUID in context for later use in middleware
	c.Set("uuid", requestUUID)
	if err := saveOTPToRedis(requestUUID, otpRequest); err != nil {
		sendAPIResponse(c, http.StatusInternalServerError, StatusRedisUnavailable, nil)
		return
	}

	// Send response with generated UUID
	responseData := map[string]interface{}{
		"uuid": requestUUID,
	}

	if cfg.Server.Mode == "test" {
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
			"request_id":        requestUUID,
		}
	}

	logger.WithFields(logrus.Fields{
		"uuid":      requestUUID,
		"client_ip": c.ClientIP(),
		"ttl":       otpRequest.TTL,
		"length":    otpRequest.CodeLength,
	}).Info("OTP generated successfully")

	sendAPIResponse(c, http.StatusOK, StatusOTPGenerated, responseData)
}

// verifyOTPHandler handles the GET request to verify an OTP
func verifyOTPHandler(c *gin.Context) {
	requestUUID := sanitizeInput(c.Query("uuid"))
	userInputOTP := sanitizeInput(c.Query("otp"))

	// Validate input
	if requestUUID == "" || userInputOTP == "" {
		sendAPIResponse(c, http.StatusBadRequest, StatusOTPMissing, nil)
		return
	}

	// Validate UUID and OTP format
	if !validateUUID(requestUUID) {
		sendAPIResponse(c, http.StatusBadRequest, StatusOTPMissing, nil)
		return
	}

	if !validateOTP(userInputOTP) {
		sendAPIResponse(c, http.StatusBadRequest, StatusOTPInvalid, nil)
		return
	}

	c.Set("uuid", requestUUID)

	// Get OTP data from Redis
	otpData, err := getOTPFromRedis(requestUUID)
	if err != nil {
		sendAPIResponse(c, http.StatusUnauthorized, StatusOTPExpired, nil)
		return
	}

	// Check if OTP is found
	if otpData.OTP == "" {
		sendAPIResponse(c, http.StatusUnauthorized, StatusOTPExpired, nil)
		return
	}

	// Check retry limit
	if otpData.RetryLimit <= 0 {
		if err := delOTPFromRedis(requestUUID); err != nil {
			sendAPIResponse(c, http.StatusInternalServerError, StatusRedisUnavailable, nil)
			return
		}
		sendAPIResponse(c, http.StatusUnauthorized, StatusOTPLimitReached, nil)
		return
	}

	// Check OTP case-insensitively if alphanumeric
	if !strings.EqualFold(otpData.OTP, userInputOTP) {
		if err := updateRetryLimitInRedis(requestUUID, otpData); err != nil {
			sendAPIResponse(c, http.StatusInternalServerError, StatusOTPInvalid, nil)
			return
		}
		sendAPIResponse(c, http.StatusUnauthorized, StatusOTPInvalid, nil)
		return
	}

	// Full body validation, if strict validation is enabled
	if otpData.StrictValidation {
		var currentData map[string]interface{}
		if err := c.ShouldBindJSON(&currentData); err != nil {
			sendAPIResponse(c, http.StatusBadRequest, StatusRequestInvalid, nil)
			return
		}

		storedDataMap := make(map[string]interface{})
		if err := json.Unmarshal(otpData.UserData, &storedDataMap); err != nil {
			sendAPIResponse(c, http.StatusInternalServerError, StatusOTPInvalid, nil)
			return
		}

		// Validate specific fields instead of deep comparison
		storedDataJSON, err := json.Marshal(storedDataMap)
		if err != nil {
			sendAPIResponse(c, http.StatusInternalServerError, StatusOTPInvalid, nil)
			return
		}
		currentDataJSON, err := json.Marshal(currentData)
		if err != nil {
			sendAPIResponse(c, http.StatusInternalServerError, StatusOTPInvalid, nil)
			return
		}
		if string(storedDataJSON) != string(currentDataJSON) {
			if err := updateRetryLimitInRedis(requestUUID, otpData); err != nil {
				sendAPIResponse(c, http.StatusInternalServerError, StatusOTPInvalid, nil)
				return
			}
			sendAPIResponse(c, http.StatusUnauthorized, StatusRequestMismatch, nil)
			return
		}
	}

	// OTP verified successfully, delete it from Redis
	if err := delOTPFromRedis(requestUUID); err != nil {
		sendAPIResponse(c, http.StatusInternalServerError, StatusRedisUnavailable, nil)
		return
	}
	// Prepare response data
	var responseData interface{} = nil
	if cfg.Server.Mode == "test" {
		responseData = map[string]interface{}{
			"test_mode": true,
			"debug_info": map[string]interface{}{
				"verified_otp":    userInputOTP,
				"original_ttl":    otpData.TTL,
				"retry_limit":     otpData.RetryLimit,
				"client_ip":       c.ClientIP(),
				"user_agent":      c.Request.UserAgent(),
				"verification_time": time.Now().Format(time.RFC3339),
			},
		}
	}
	sendAPIResponse(c, http.StatusOK, StatusOTPVerified, responseData)
}

// updateRetryLimitInRedis updates the retry limit for an OTP in Redis without resetting the TTL
func updateRetryLimitInRedis(uuid string, otpData *OTPRequest) error {
	otpData.RetryLimit--

	// Get current TTL from Redis to avoid resetting it
	retrieveCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	shardIndex := getShardIndex(uuid)
	if err := redisClient.Do(retrieveCtx, "SELECT", shardIndex).Err(); err != nil {
		logger.Errorf("error selecting Redis index: %v", err)
		return fmt.Errorf("error selecting Redis index: %v", err)
	}
	ttl, err := redisClient.TTL(retrieveCtx, getRedisKey(uuid)).Result()
	if err != nil {
		logger.Errorf("error retrieving TTL from Redis: %v", err)
		return fmt.Errorf("error retrieving TTL from Redis: %v", err)
	}

	// Marshal OTP data to JSON
	otpJSON, err := json.Marshal(otpData)
	if err != nil {
		logger.Errorf("error marshaling OTP data: %v", err)
		return fmt.Errorf("error marshaling OTP data: %v", err)
	}

	// Save updated OTP data with the same TTL
	if err := redisClient.Set(retrieveCtx, getRedisKey(uuid), otpJSON, ttl).Err(); err != nil {
		logger.Errorf("error saving updated OTP to Redis: %v", err)
		return fmt.Errorf("error saving updated OTP to Redis: %v", err)
	}
	logger.Infof("Successfully updated RetryLimit for UUID: %s", uuid)
	return nil
}

// Main function with TLS support and graceful shutdown
func main() {

	// Set up Gin with security headers
	// Set up Gin router with CORS
	gin.SetMode(gin.ReleaseMode)

	switch cfg.Server.Mode {
	case "debug":
		gin.SetMode(gin.DebugMode)
	case "test":
		gin.SetMode(gin.TestMode)
	}

	r := gin.New()
	r.Use(
		gin.Recovery(),
		securityHeadersMiddleware(),
	)

	// Set up TLS
	var tlsConfig *tls.Config
	if cfg.Server.TLS.Enabled {
		cert, err := tls.LoadX509KeyPair(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
		if err != nil {
			handleFatalError("Failed to load TLS certificates", err)
		}

		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}

	// Register routes
	r.POST("/", generateOTPHandler)
	r.GET("/", verifyOTPHandler)

	// Health check route, utilizing middleware for status check
	r.GET("/health", func(c *gin.Context) {

		// Prepare response data with sensitive config masking
		responseData := map[string]interface{}{
			"redis_status": "OK",
			"config":       "***********",
			"server_mode":  cfg.Server.Mode,
		}
		if cfg.Server.Mode == "debug" {
			responseData["config"] = cfg
		} else if cfg.Server.Mode == "test" {
			responseData["test_mode"] = true
			responseData["debug_features"] = map[string]interface{}{
				"otp_visible_in_generation": true,
				"detailed_debug_info":       true,
				"request_tracking":          true,
			}
			// Show some config details but not sensitive ones
			responseData["config_summary"] = map[string]interface{}{
				"redis_host":   cfg.Redis.Host,
				"redis_port":   cfg.Redis.Port,
				"server_host":  cfg.Server.Host,
				"server_port":  cfg.Server.Port,
				"hash_keys":    cfg.Config.HashKeys,
			}
		}

		sendAPIResponse(c, http.StatusOK, StatusServiceHealth, responseData)
	})

	// Set up HTTP server with timeouts
	server := &http.Server{
		Addr:              fmt.Sprintf("%s:%s", cfg.Server.Host, cfg.Server.Port),
		Handler:           r,
		TLSConfig:         tlsConfig,
		ReadTimeout:       time.Duration(cfg.Server.Timeout.Read) * time.Second,
		WriteTimeout:      time.Duration(cfg.Server.Timeout.Write) * time.Second,
		IdleTimeout:       time.Duration(cfg.Server.Timeout.Idle) * time.Second,
		ReadHeaderTimeout: time.Duration(cfg.Server.Timeout.ReadHeader) * time.Second,
	}

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-quit
		logger.Info("Shutting down server...")

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			logger.Fatalf("Server forced to shutdown: %v", err)
		}

		if err := redisClient.Close(); err != nil {
			logger.Errorf("Error closing Redis client: %v", err)
		}
	}()

	// Start server
	logger.Infof("Starting server on %s", server.Addr)
	if cfg.Server.TLS.Enabled {
		if err := server.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			handleFatalError("Failed to start server", err)
		}
	} else {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			handleFatalError("Failed to start server", err)
		}
	}
}

// securityHeadersMiddleware adds security headers to the response
func securityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Clickjacking Protection
		c.Header("X-Frame-Options", "DENY")

		// Prevent MIME type sniffing
		c.Header("X-Content-Type-Options", "nosniff")

		// XSS Protection in browsers
		c.Header("X-XSS-Protection", "1; mode=block")

		//
		c.Header("X-Permitted-Cross-Domain-Policies", "none")

		// Content Security Policy Configuration
		csp := []string{
			"default-src 'self'",
			"script-src 'self' 'unsafe-inline' 'unsafe-eval'",
			"style-src 'self' 'unsafe-inline'",
			"img-src 'self' data:",
			"font-src 'self'",
			"form-action 'self'",
			"frame-ancestors 'none'",
			"base-uri 'self'",
			"block-all-mixed-content",
		}
		c.Header("Content-Security-Policy", strings.Join(csp, "; "))

		// Add Referrer Policy
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

		// تنظیم HSTS - فقط در محیط production با SSL
		// HSTS Configuration - Only in production environment with SSL
		if cfg.Server.TLS.Enabled {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}
		c.Header("X-Download-Options", "noopen")
		c.Header("X-DNS-Prefetch-Control", "off")

		// Prevent caching sensitive data
		c.Header("Cache-Control", "no-store, max-age=0")
		c.Header("Pragma", "no-cache")

		// Limit information leakage about the server
		c.Header("X-Powered-By", "")
		c.Header("Server", "")

		// Add Permissions-Policy header
		featurePolicy := []string{
			"camera 'none'",
			"microphone 'none'",
			"geolocation 'none'",
			"payment 'none'",
			"usb 'none'",
			"fullscreen 'self'",
		}
		c.Header("Permissions-Policy", strings.Join(featurePolicy, ", "))

		// Cross-Origin-Embedder-Policy
		c.Header("Cross-Origin-Embedder-Policy", "require-corp")

		// Cross-Origin-Opener-Policy
		c.Header("Cross-Origin-Opener-Policy", "same-origin")

		// Cross-Origin-Resource-Policy
		c.Header("Cross-Origin-Resource-Policy", "same-origin")

		c.Next()
	}
}
