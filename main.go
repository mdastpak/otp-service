package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var (
	logger      = logrus.New()
	config      Config
	ctx         = context.Background()
	redisClient *redis.Client
)

// Config structure to hold server, redis, and general configurations
type Config struct {
	Redis struct {
		Host      string `mapstructure:"HOST"`
		Port      string `mapstructure:"PORT"`
		Password  string `mapstructure:"PASSWORD"`
		Indices   string `mapstructure:"INDICES"`
		KeyPrefix string `mapstructure:"KEY_PREFIX"`
		Timeout   int    `mapstructure:"TIMEOUT"`
	} `mapstructure:"REDIS"`
	Server struct {
		Host  string `mapstructure:"HOST"`
		Port  string `mapstructure:"PORT"`
		Debug bool   `mapstructure:"DEBUG"`
	} `mapstructure:"SERVER"`
	Config struct {
		HashKeys bool `mapstructure:"HASH_KEYS"`
	} `mapstructure:"CONFIG"`
}

const (
	StatusOTPGenearted      = "OTP_GENERATED"
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
	viper.BindEnv("REDIS.HOST", "REDIS_HOST")
	viper.BindEnv("REDIS.PORT", "REDIS_PORT")
	viper.BindEnv("REDIS.PASSWORD", "REDIS_PASSWORD")
	viper.BindEnv("REDIS.KEY_PREFIX", "REDIS_KEY_PREFIX")
	viper.BindEnv("REDIS.TIMEOUT", "REDIS_TIMEOUT")
	viper.BindEnv("SERVER.HOST", "SERVER_HOST")
	viper.BindEnv("SERVER.PORT", "SERVER_PORT")
	viper.BindEnv("SERVER.DEBUG", "SERVER_DEBUG")
	viper.BindEnv("CONFIG.HASH_KEYS", "HASH_KEYS")

	// Unmarshal configuration into Config struct
	if err := viper.Unmarshal(&config); err != nil {
		handleFatalError("Unable to decode into struct", err)
	}
}

// initRedis initializes the Redis client and checks the connection.
func initRedis() {
	redisClient = redis.NewClient(&redis.Options{
		Addr:         fmt.Sprintf("%s:%s", config.Redis.Host, config.Redis.Port),
		Password:     config.Redis.Password,
		ReadTimeout:  time.Duration(config.Redis.Timeout) * time.Second,
		WriteTimeout: time.Duration(config.Redis.Timeout) * time.Second,
	})

	// Test Redis connection with a context timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(config.Redis.Timeout)*time.Second)
	defer cancel()

	_, err := redisClient.Ping(ctx).Result()
	if err != nil {
		handleFatalError("Failed to connect to Redis", err)
	}
	logger.Info("Connected to Redis successfully")
}

func init() {
	// Initialize logger
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetLevel(logrus.DebugLevel)

	// Load configuration
	loadConfig()

	// Initialize Redis client
	initRedis()

	if !config.Server.Debug {
		logger.SetLevel(logrus.InfoLevel)
	}
}

// handleFatalError logs a fatal error and terminates the program
func handleFatalError(message string, err error) {
	logger.Fatalf("%s: %v", message, err)
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

	lastRequestTimeStr, err := redisClient.Get(limiterCtx, redisKey).Result()
	if err == nil {
		lastRequestTime, err := time.Parse(time.RFC3339, lastRequestTimeStr)
		if err == nil && time.Since(lastRequestTime) < time.Minute {
			return true
		}
	}

	// Update last request time in Redis
	_ = redisClient.Set(limiterCtx, redisKey, time.Now().Format(time.RFC3339), time.Minute).Err()
	return false
}

// generateOTP generates a random OTP code based on the given length and character set complexity
func generateOTP(codeLength int, useAlphaNumeric bool) (string, error) {
	var charSet string
	if useAlphaNumeric {
		charSet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	} else {
		charSet = "0123456789"
	}

	otpCode := make([]byte, codeLength)
	for i := 0; i < codeLength; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charSet))))
		if err != nil {
			return "", err
		}
		otpCode[i] = charSet[num.Int64()]
	}
	return string(otpCode), nil
}

// generateRedisKey generates a Redis key using SHA-256 hash of the request UUID
func generateRedisKey(requestUUID string) string {
	hash := sha256.Sum256([]byte(requestUUID))
	return hex.EncodeToString(hash[:])
}

// getRedisKey generates the final Redis key using the configuration settings
func getRedisKey(uuid string) string {
	key := uuid
	if config.Config.HashKeys {
		key = generateRedisKey(uuid)
	}
	if config.Redis.KeyPrefix != "" {
		key = fmt.Sprintf("%s:%s", config.Redis.KeyPrefix, key)
	}
	return key
}

// getShardIndex determines the appropriate Redis shard index based on UUID
func getShardIndex(uuid string) int {
	rangeParts := strings.Split(config.Redis.Indices, "-")
	if config.Redis.Indices == "0" {
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

// healthCheckMiddleware is a middleware that checks the health of Redis before processing each request
func healthCheckMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		healthCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()

		// Check Redis health before processing request
		if _, err := redisClient.Ping(healthCtx).Result(); err != nil {
			// Prepare response data with sensitive config masking
			responseData := map[string]interface{}{
				"redis_status": "Unavailable",
				"config":       config,
			}
			if !config.Server.Debug {
				responseData["config"] = "***********"
			}

			sendAPIResponse(c, http.StatusServiceUnavailable, StatusServiceHealth, responseData)
			c.Abort()
			return
		}
		c.Next()
	}
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
	c.Set("uuid", requestUUID)
	if err := saveOTPToRedis(requestUUID, otpRequest); err != nil {
		sendAPIResponse(c, http.StatusInternalServerError, StatusRedisUnavailable, nil)
		return
	}

	// Send response with generated UUID
	sendAPIResponse(c, http.StatusOK, StatusOTPGenearted, map[string]string{
		"uuid": requestUUID,
	})
}

// verifyOTPHandler handles the GET request to verify an OTP
func verifyOTPHandler(c *gin.Context) {
	requestUUID := c.Query("uuid")
	userInputOTP := c.Query("otp")

	// Validate input
	if requestUUID == "" || userInputOTP == "" {
		sendAPIResponse(c, http.StatusBadRequest, StatusOTPMissing, nil)
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
	sendAPIResponse(c, http.StatusOK, StatusOTPVerified, nil)
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

// main function with graceful shutdown
func main() {
	// Load configuration
	loadConfig()

	// Initialize Redis with error handling
	initRedis()

	// Set up Gin router with CORS
	if config.Server.Debug {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.Default()
	r.Use(cors.New(cors.Config{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{"GET", "POST"},
		AllowHeaders: []string{"Origin", "Content-Type"},
	}))
	r.Use(gin.Logger())
	r.Use(healthCheckMiddleware())

	// Register routes
	r.POST("/", generateOTPHandler)
	r.GET("/", verifyOTPHandler)

	// Health check route, utilizing middleware for status check
	r.GET("/health", func(c *gin.Context) {

		// Prepare response data with sensitive config masking
		responseData := map[string]interface{}{
			"redis_status": "OK",
			"config":       config,
		}
		if !config.Server.Debug {
			responseData["config"] = "***********"
		}

		sendAPIResponse(c, http.StatusOK, StatusServiceHealth, responseData)
	})

	// Set up server
	serverAddress := fmt.Sprintf("%s:%s", config.Server.Host, config.Server.Port)
	server := &http.Server{
		Addr:    serverAddress,
		Handler: r,
	}

	// Channel to listen for OS interrupt signals for graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Goroutine to handle shutdown when signal is received
	go func() {
		<-quit
		logger.Info("Shutting down server...")

		// Create a context with timeout for graceful shutdown
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Attempt to gracefully shutdown the server
		if err := server.Shutdown(ctx); err != nil {
			handleFatalError("Server forced to shutdown", err)
		}

		// Close Redis connection
		if err := redisClient.Close(); err != nil {
			handleFatalError("Error closing Redis client", err)
		} else {
			logger.Info("Redis client closed successfully")
		}

		logger.Info("Server exiting")
	}()

	// Start the server
	logger.Infof("Starting server on port %s", serverAddress)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		handleFatalError("Server failed to start", err)
	}
}
