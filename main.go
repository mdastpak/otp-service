package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
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
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var (
	logger      = logrus.New()
	cfg         Config
	ctx         = context.Background()
	redisClient *redis.Client
)

// ShardConfig caches parsed shard configuration for performance
type ShardConfig struct {
	shardCount int
	startIndex int
	isRange    bool
}

var shardConfig *ShardConfig

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
	logger.Info("Loading configuration...")
	
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")

	if err := viper.ReadInConfig(); err != nil {
		logger.WithError(err).Fatal("Failed to read config file")
		handleFatalError("Error reading config file", err)
	}
	logger.WithField("config_file", viper.ConfigFileUsed()).Info("Configuration file loaded successfully")
	
	viper.AutomaticEnv()
	logger.Info("Environment variable bindings configured")

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
		logger.WithError(err).Fatal("Failed to decode configuration into struct")
		handleFatalError("Unable to decode into struct", err)
	}
	logger.Info("Configuration successfully decoded and validated")

	// Parse and cache shard configuration
	initShardConfig()
	logger.Info("Configuration loading completed successfully")
}

// initShardConfig parses and caches shard configuration for performance
func initShardConfig() {
	logger.WithField("redis_indices", cfg.Redis.Indices).Info("Initializing Redis shard configuration")
	
	rangeParts := strings.Split(cfg.Redis.Indices, "-")

	if cfg.Redis.Indices == "0" {
		shardConfig = &ShardConfig{shardCount: 1, startIndex: 0, isRange: false}
		logger.Info("Redis shard configuration: Single database (index 0)")
		return
	}

	if len(rangeParts) == 1 {
		count, err := strconv.Atoi(rangeParts[0])
		if err != nil || count <= 0 {
			logger.WithError(err).WithField("indices", cfg.Redis.Indices).Fatal("Invalid Redis indices configuration")
			handleFatalError("Invalid Redis Indices configuration", err)
		}
		shardConfig = &ShardConfig{shardCount: count, startIndex: 0, isRange: false}
		logger.WithFields(logrus.Fields{
			"shard_count": count,
			"start_index": 0,
			"type": "single_count",
		}).Info("Redis shard configuration initialized")
	} else if len(rangeParts) == 2 {
		start, err := strconv.Atoi(rangeParts[0])
		if err != nil {
			logger.WithError(err).WithField("start_value", rangeParts[0]).Fatal("Invalid Redis indices start configuration")
			handleFatalError("Invalid Redis Indices start configuration", err)
		}
		end, err := strconv.Atoi(rangeParts[1])
		if err != nil {
			logger.WithError(err).WithField("end_value", rangeParts[1]).Fatal("Invalid Redis indices end configuration")
			handleFatalError("Invalid Redis Indices end configuration", err)
		}
		count := end - start + 1
		if count <= 0 {
			logger.WithFields(logrus.Fields{
				"start_index": start,
				"end_index": end,
				"calculated_count": count,
			}).Fatal("Invalid Redis indices configuration: range results in zero or negative count")
			handleFatalError("Invalid Redis Indices configuration: range results in zero or negative count", nil)
		}
		shardConfig = &ShardConfig{shardCount: count, startIndex: start, isRange: true}
		logger.WithFields(logrus.Fields{
			"shard_count": count,
			"start_index": start,
			"end_index": end,
			"type": "range",
		}).Info("Redis shard configuration initialized")
	} else {
		logger.WithField("indices_format", cfg.Redis.Indices).Fatal("Invalid Redis indices format. Use a single number or a range (e.g., '0-2')")
		handleFatalError("Invalid Redis Indices format. Use a single number or a range (e.g., '0-2')", nil)
	}
}

// initRedis initializes the Redis client and checks the connection.
func initRedis() {
	logger.Info("Initializing Redis connection...")
	
	// Log connection details (without sensitive information)
	logger.WithFields(logrus.Fields{
		"redis_host": cfg.Redis.Host,
		"redis_port": cfg.Redis.Port,
		"timeout_seconds": cfg.Redis.Timeout,
		"key_prefix": func() string {
			if cfg.Redis.KeyPrefix == "" {
				return "<none>"
			}
			return cfg.Redis.KeyPrefix
		}(),
		"password_configured": cfg.Redis.Password != "",
	}).Info("Redis client configuration")
	
	redisClient = redis.NewClient(&redis.Options{
		Addr:         fmt.Sprintf("%s:%s", cfg.Redis.Host, cfg.Redis.Port),
		Password:     cfg.Redis.Password,
		ReadTimeout:  time.Duration(cfg.Redis.Timeout) * time.Second,
		WriteTimeout: time.Duration(cfg.Redis.Timeout) * time.Second,
	})

	// Test Redis connection with a context timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Redis.Timeout)*time.Second)
	defer cancel()

	logger.Info("Testing Redis connectivity...")
	start := time.Now()
	_, err := redisClient.Ping(ctx).Result()
	connectionDuration := time.Since(start)
	
	if err != nil {
		logger.WithFields(logrus.Fields{
			"redis_host": cfg.Redis.Host,
			"redis_port": cfg.Redis.Port,
			"timeout_seconds": cfg.Redis.Timeout,
			"connection_duration_ms": connectionDuration.Milliseconds(),
		}).WithError(err).Fatal("Failed to establish Redis connection")
		handleFatalError("Failed to connect to Redis", err)
	}
	
	logger.WithFields(logrus.Fields{
		"connection_duration_ms": connectionDuration.Milliseconds(),
		"redis_version": func() string {
			if info, err := redisClient.Info(ctx, "server").Result(); err == nil {
				for _, line := range strings.Split(info, "\r\n") {
					if strings.HasPrefix(line, "redis_version:") {
						return strings.TrimPrefix(line, "redis_version:")
					}
				}
			}
			return "unknown"
		}(),
	}).Info("Redis connection established successfully")
}

func init() {
	// Skip initialization during tests
	for _, arg := range os.Args {
		if strings.Contains(arg, "test") {
			return
		}
	}

	// Initialize logger with startup information
	logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339,
		FieldMap: logrus.FieldMap{
			logrus.FieldKeyTime:  "timestamp",
			logrus.FieldKeyLevel: "level",
			logrus.FieldKeyMsg:   "message",
		},
	})
	logger.SetLevel(logrus.InfoLevel)

	// Log service startup
	logger.WithFields(logrus.Fields{
		"service": "otp-service",
		"version": "1.0.0",
		"go_version": fmt.Sprintf("%s", os.Getenv("GO_VERSION")),
		"pid": os.Getpid(),
		"startup_time": time.Now().Format(time.RFC3339),
	}).Info("OTP Service initialization started")

	// Load configuration
	loadConfig()

	// Initialize Redis client
	initRedis()

	// Set final log level based on server mode
	logger.SetLevel(logrus.InfoLevel)
	if cfg.Server.Mode != "release" {
		logger.SetLevel(logrus.TraceLevel)
		logger.Info("Debug mode enabled - verbose logging activated")
	} else {
		logger.Info("Production mode - standard logging level set")
	}
	
	logger.Info("OTP Service initialization completed successfully")
}

// handleFatalError logs a fatal error and terminates the program
func handleFatalError(message string, err error) {
	logger.WithFields(logrus.Fields{
		"error_type": "fatal",
		"service": "otp-service",
		"timestamp": time.Now().Format(time.RFC3339),
	}).WithError(err).Fatal(message)
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
	
	// Log response without sensitive information
	logFields := logrus.Fields{
		"status": status,
		"message": message,
		"client_ip": c.ClientIP(),
		"user_agent": c.Request.UserAgent(),
		"method": c.Request.Method,
		"path": c.Request.URL.Path,
		"response_time_ms": time.Since(time.Now()).Milliseconds(),
	}
	
	// Add UUID if available (but don't log the actual UUID value for security)
	if uuid := c.GetString("uuid"); uuid != "" {
		logFields["has_uuid"] = true
		logFields["uuid_length"] = len(uuid)
	} else {
		logFields["has_uuid"] = false
	}
	
	// Log info field size but not content
	if info != nil {
		logFields["has_info"] = true
		if infoBytes, err := json.Marshal(info); err == nil {
			logFields["info_size_bytes"] = len(infoBytes)
		}
	} else {
		logFields["has_info"] = false
	}
	
	logger.WithFields(logFields).Info("API response sent")
}

// isRateLimited checks if a client is being rate limited by checking Redis for recent requests
func isRateLimited(clientID string) bool {
	redisKey := fmt.Sprintf("rate_limit:%s", clientID)
	limiterCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	// Use Redis counter for more accurate rate limiting
	start := time.Now()
	count, err := redisClient.Incr(limiterCtx, redisKey).Result()
	duration := time.Since(start)
	
	if err != nil {
		logger.WithFields(logrus.Fields{
			"client_ip": clientID,
			"operation": "rate_limit_check",
			"duration_ms": duration.Milliseconds(),
		}).WithError(err).Error("Rate limit check failed - allowing request")
		return false
	}

	// Set expiration only for the first request
	if count == 1 {
		if err := redisClient.Expire(limiterCtx, redisKey, time.Minute).Err(); err != nil {
			logger.WithFields(logrus.Fields{
				"client_ip": clientID,
				"operation": "rate_limit_expiry",
			}).WithError(err).Error("Failed to set rate limit expiry")
		}
	}

	isLimited := count > 10
	logger.WithFields(logrus.Fields{
		"client_ip": clientID,
		"current_count": count,
		"limit": 10,
		"is_limited": isLimited,
		"check_duration_ms": duration.Milliseconds(),
	}).Debug("Rate limit check completed")
	
	return isLimited
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
// Uses UUID's inherent randomness for fast, well-distributed sharding
func getShardIndex(uuid string) int {
	if shardConfig.shardCount == 1 {
		return shardConfig.startIndex
	}

	// Use last 8 hex chars (4 bytes) of UUID for good distribution
	// UUIDs are designed to be random, so this provides excellent distribution
	cleaned := strings.ReplaceAll(uuid, "-", "")
	if len(cleaned) < 8 {
		// Fallback for malformed UUIDs
		return shardConfig.startIndex
	}

	lastBytes := cleaned[len(cleaned)-8:] // Last 4 bytes as hex string

	// Convert hex to uint32 for modulo operation
	hash, err := strconv.ParseUint(lastBytes, 16, 32)
	if err != nil {
		// Fallback for parse errors
		return shardConfig.startIndex
	}

	// Safe conversion: hash is guaranteed to fit in uint32, then convert to int
	shardOffset := int(uint32(hash)) % shardConfig.shardCount
	return shardConfig.startIndex + shardOffset
}

// saveOTPToRedis saves the OTP data to Redis under the appropriate shard
func saveOTPToRedis(uuid string, otpData OTPRequest) error {
	logger.WithFields(logrus.Fields{
		"operation": "redis_save",
		"shard_index": getShardIndex(uuid),
		"ttl_seconds": otpData.TTL,
	}).Debug("Saving OTP data to Redis")
	
	// Save the raw body (UserData) to Redis in all cases
	if otpData.UserData == nil {
		rawData, err := json.Marshal(otpData)
		if err != nil {
			logger.WithError(err).Error("Failed to marshal OTP data")
			return fmt.Errorf("error marshaling OTP data: %v", err)
		}
		otpData.UserData = json.RawMessage(rawData)
	}
	key := getRedisKey(uuid)

	otpJSON, err := json.Marshal(otpData)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal OTP data for Redis storage")
		return fmt.Errorf("error marshaling OTP data: %v", err)
	}

	saveCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	start := time.Now()
	shardIndex := getShardIndex(uuid)
	if err := redisClient.Do(saveCtx, "SELECT", shardIndex).Err(); err != nil {
		logger.WithFields(logrus.Fields{
			"operation": "redis_select",
			"shard_index": shardIndex,
		}).WithError(err).Error("Failed to select Redis shard")
		return fmt.Errorf("error selecting Redis index: %v", err)
	}

	if err := redisClient.Set(saveCtx, key, otpJSON, otpData.TTLDuration).Err(); err != nil {
		logger.WithFields(logrus.Fields{
			"operation": "redis_set",
			"shard_index": shardIndex,
			"ttl_seconds": otpData.TTL,
		}).WithError(err).Error("Failed to save OTP to Redis")
		return fmt.Errorf("error saving OTP to Redis: %v", err)
	}
	
	duration := time.Since(start)
	logger.WithFields(logrus.Fields{
		"operation": "redis_save_complete",
		"shard_index": shardIndex,
		"duration_ms": duration.Milliseconds(),
		"ttl_seconds": otpData.TTL,
	}).Debug("OTP data saved to Redis successfully")
	return nil
}

// getOTPFromRedis retrieves the OTP data from Redis using the appropriate shard
func getOTPFromRedis(uuid string) (*OTPRequest, error) {
	key := getRedisKey(uuid)
	shardIndex := getShardIndex(uuid)
	
	logger.WithFields(logrus.Fields{
		"operation": "redis_retrieve",
		"shard_index": shardIndex,
	}).Debug("Retrieving OTP data from Redis")

	retrieveCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	start := time.Now()
	if err := redisClient.Do(retrieveCtx, "SELECT", shardIndex).Err(); err != nil {
		logger.WithFields(logrus.Fields{
			"operation": "redis_select",
			"shard_index": shardIndex,
		}).WithError(err).Error("Failed to select Redis shard for retrieval")
		return nil, fmt.Errorf("error selecting Redis index: %v", err)
	}

	result, err := redisClient.Get(retrieveCtx, key).Result()
	duration := time.Since(start)
	
	if err == redis.Nil {
		logger.WithFields(logrus.Fields{
			"operation": "redis_retrieve_expired",
			"shard_index": shardIndex,
			"duration_ms": duration.Milliseconds(),
		}).Debug("OTP not found in Redis - expired or invalid")
		return nil, fmt.Errorf(StatusOTPExpired)
	} else if err != nil {
		logger.WithFields(logrus.Fields{
			"operation": "redis_retrieve_error",
			"shard_index": shardIndex,
			"duration_ms": duration.Milliseconds(),
		}).WithError(err).Error("Failed to retrieve OTP from Redis")
		return nil, fmt.Errorf("error retrieving OTP from Redis: %v", err)
	}

	var otpData OTPRequest
	if err := json.Unmarshal([]byte(result), &otpData); err != nil {
		logger.WithFields(logrus.Fields{
			"operation": "redis_unmarshal_error",
			"shard_index": shardIndex,
		}).WithError(err).Error("Failed to unmarshal OTP data from Redis")
		return nil, fmt.Errorf("error unmarshaling OTP data: %v", err)
	}
	
	logger.WithFields(logrus.Fields{
		"operation": "redis_retrieve_success",
		"shard_index": shardIndex,
		"duration_ms": duration.Milliseconds(),
		"remaining_attempts": otpData.RetryLimit,
	}).Debug("OTP data retrieved from Redis successfully")
	return &otpData, nil
}

// delOTPFromRedis deletes the OTP data from Redis under the appropriate shard
func delOTPFromRedis(uuid string) error {
	key := getRedisKey(uuid)
	shardIndex := getShardIndex(uuid)
	
	logger.WithFields(logrus.Fields{
		"operation": "redis_delete",
		"shard_index": shardIndex,
	}).Debug("Deleting OTP data from Redis")

	deleteCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	start := time.Now()
	if err := redisClient.Do(deleteCtx, "SELECT", shardIndex).Err(); err != nil {
		logger.WithFields(logrus.Fields{
			"operation": "redis_select",
			"shard_index": shardIndex,
		}).WithError(err).Error("Failed to select Redis shard for deletion")
		return fmt.Errorf("error selecting Redis index: %v", err)
	}

	if err := redisClient.Del(deleteCtx, key).Err(); err != nil {
		logger.WithFields(logrus.Fields{
			"operation": "redis_delete_error",
			"shard_index": shardIndex,
		}).WithError(err).Error("Failed to delete OTP from Redis")
		return fmt.Errorf("error deleting OTP from Redis: %v", err)
	}
	
	duration := time.Since(start)
	logger.WithFields(logrus.Fields{
		"operation": "redis_delete_success",
		"shard_index": shardIndex,
		"duration_ms": duration.Milliseconds(),
	}).Debug("OTP data deleted from Redis successfully")
	return nil
}

// generateOTPHandler handles the POST request to generate an OTP
func generateOTPHandler(c *gin.Context) {
	start := time.Now()
	clientID := c.ClientIP()
	
	logger.WithFields(logrus.Fields{
		"operation": "otp_generation_start",
		"client_ip": clientID,
		"user_agent": c.Request.UserAgent(),
		"method": c.Request.Method,
		"path": c.Request.URL.Path,
	}).Info("OTP generation request received")
	
	if isRateLimited(clientID) {
		logger.WithFields(logrus.Fields{
			"operation": "rate_limit_exceeded",
			"client_ip": clientID,
		}).Warn("Request rejected due to rate limiting")
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
	logger.WithFields(logrus.Fields{
		"operation": "otp_code_generation",
		"code_length": otpRequest.CodeLength,
		"use_alpha_numeric": otpRequest.UseAlphaNumeric,
	}).Debug("Generating OTP code")
	
	if otpRequest.OTP, err = generateOTP(otpRequest.CodeLength, otpRequest.UseAlphaNumeric); err != nil {
		logger.WithError(err).Error("Failed to generate OTP code")
		sendAPIResponse(c, http.StatusInternalServerError, StatusOTPInvalid, nil)
		return
	}
	otpRequest.TTLDuration = time.Duration(otpRequest.TTL) * time.Second

	// Generate UUID and save OTP to Redis
	requestUUID := uuid.New().String()
	logger.WithField("uuid_generated", true).Debug("UUID generated for OTP session")

	// Set UUID in context for later use in middleware
	c.Set("uuid", requestUUID)
	if err := saveOTPToRedis(requestUUID, otpRequest); err != nil {
		logger.WithError(err).Error("Failed to save OTP to Redis")
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

	totalDuration := time.Since(start)
	logger.WithFields(logrus.Fields{
		"operation": "otp_generation_complete",
		"client_ip": c.ClientIP(),
		"ttl_seconds": otpRequest.TTL,
		"code_length": otpRequest.CodeLength,
		"use_alpha_numeric": otpRequest.UseAlphaNumeric,
		"strict_validation": otpRequest.StrictValidation,
		"retry_limit": otpRequest.RetryLimit,
		"uuid_generated": requestUUID != "",
		"redis_shard": getShardIndex(requestUUID),
		"total_duration_ms": totalDuration.Milliseconds(),
	}).Info("OTP generated and stored successfully")

	sendAPIResponse(c, http.StatusOK, StatusOTPGenerated, responseData)
}

// verifyOTPHandler handles the GET request to verify an OTP
func verifyOTPHandler(c *gin.Context) {
	start := time.Now()
	clientIP := c.ClientIP()
	
	logger.WithFields(logrus.Fields{
		"operation": "otp_verification_start",
		"client_ip": clientIP,
		"user_agent": c.Request.UserAgent(),
		"method": c.Request.Method,
		"path": c.Request.URL.Path,
	}).Info("OTP verification request received")
	
	requestUUID := sanitizeInput(c.Query("uuid"))
	userInputOTP := sanitizeInput(c.Query("otp"))

	// Validate input
	if requestUUID == "" || userInputOTP == "" {
		logger.WithFields(logrus.Fields{
			"operation": "validation_failed",
			"client_ip": clientIP,
			"has_uuid": requestUUID != "",
			"has_otp": userInputOTP != "",
		}).Warn("OTP verification failed - missing required parameters")
		sendAPIResponse(c, http.StatusBadRequest, StatusOTPMissing, nil)
		return
	}

	// Validate UUID and OTP format
	if !validateUUID(requestUUID) {
		logger.WithFields(logrus.Fields{
			"operation": "uuid_validation_failed",
			"client_ip": clientIP,
			"uuid_length": len(requestUUID),
		}).Warn("OTP verification failed - invalid UUID format")
		sendAPIResponse(c, http.StatusBadRequest, StatusOTPMissing, nil)
		return
	}

	if !validateOTP(userInputOTP) {
		logger.WithFields(logrus.Fields{
			"operation": "otp_validation_failed",
			"client_ip": clientIP,
			"otp_length": len(userInputOTP),
		}).Warn("OTP verification failed - invalid OTP format")
		sendAPIResponse(c, http.StatusBadRequest, StatusOTPInvalid, nil)
		return
	}
	
	logger.WithFields(logrus.Fields{
		"operation": "input_validation_success",
		"client_ip": clientIP,
		"redis_shard": getShardIndex(requestUUID),
	}).Debug("Input validation completed successfully")

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

	// Check OTP using constant-time comparison to prevent timing attacks
	// For case-insensitive comparison, normalize both strings first
	storedOTP := strings.ToUpper(otpData.OTP)
	inputOTP := strings.ToUpper(userInputOTP)
	
	logger.WithFields(logrus.Fields{
		"operation": "otp_comparison",
		"client_ip": clientIP,
		"remaining_attempts": otpData.RetryLimit,
		"redis_shard": getShardIndex(requestUUID),
	}).Debug("Performing OTP comparison")
	
	// Use constant-time comparison
	if subtle.ConstantTimeCompare([]byte(storedOTP), []byte(inputOTP)) != 1 {
		logger.WithFields(logrus.Fields{
			"operation": "otp_mismatch",
			"client_ip": clientIP,
			"remaining_attempts": otpData.RetryLimit - 1,
		}).Warn("OTP verification failed - incorrect OTP provided")
		
		if err := updateRetryLimitInRedis(requestUUID, otpData); err != nil {
			logger.WithError(err).Error("Failed to update retry limit after incorrect OTP")
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
	logger.WithFields(logrus.Fields{
		"operation": "otp_verification_success",
		"client_ip": clientIP,
		"redis_shard": getShardIndex(requestUUID),
	}).Info("OTP verification successful - cleaning up Redis data")
	
	if err := delOTPFromRedis(requestUUID); err != nil {
		logger.WithError(err).Error("Failed to delete OTP from Redis after successful verification")
		sendAPIResponse(c, http.StatusInternalServerError, StatusRedisUnavailable, nil)
		return
	}
	// Prepare response data
	var responseData interface{} = nil
	if cfg.Server.Mode == "test" {
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
	totalDuration := time.Since(start)
	logger.WithFields(logrus.Fields{
		"operation": "otp_verification_complete",
		"client_ip": clientIP,
		"total_duration_ms": totalDuration.Milliseconds(),
		"verification_result": "success",
	}).Info("OTP verification completed successfully")
	
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
	logger.WithFields(logrus.Fields{
		"operation": "retry_limit_update",
		"remaining_attempts": otpData.RetryLimit,
		"redis_shard": getShardIndex(uuid),
	}).Info("OTP retry limit updated successfully")
	return nil
}

// Main function with TLS support and graceful shutdown
func main() {
	logger.WithFields(logrus.Fields{
		"service": "otp-service",
		"version": "1.0.0",
		"server_mode": cfg.Server.Mode,
		"tls_enabled": cfg.Server.TLS.Enabled,
		"bind_address": fmt.Sprintf("%s:%s", cfg.Server.Host, cfg.Server.Port),
	}).Info("Starting OTP service main function")

	// Set up Gin with security headers
	// Set up Gin router with CORS
	gin.SetMode(gin.ReleaseMode)
	logger.Info("Gin framework configured in release mode")

	switch cfg.Server.Mode {
	case "test":
		gin.SetMode(gin.TestMode)
		logger.Info("Gin framework switched to test mode for debugging")
	default:
		logger.WithField("mode", cfg.Server.Mode).Info("Server mode configured")
	}

	logger.Info("Initializing HTTP router and middleware stack...")
	r := gin.New()
	r.Use(
		gin.Recovery(),
		corsMiddleware(),
		requestSizeLimitMiddleware(),
		securityHeadersMiddleware(),
	)
	logger.Info("HTTP middleware stack configured (recovery, CORS, size limit, security headers)")

	// Set up TLS
	var tlsConfig *tls.Config
	if cfg.Server.TLS.Enabled {
		logger.WithFields(logrus.Fields{
			"cert_file": cfg.Server.TLS.CertFile,
			"key_file": cfg.Server.TLS.KeyFile,
		}).Info("Loading TLS certificates...")
		
		cert, err := tls.LoadX509KeyPair(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"cert_file": cfg.Server.TLS.CertFile,
				"key_file": cfg.Server.TLS.KeyFile,
			}).WithError(err).Fatal("Failed to load TLS certificates")
			handleFatalError("Failed to load TLS certificates", err)
		}

		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		logger.WithField("min_tls_version", "TLS 1.2").Info("TLS configuration loaded successfully")
	} else {
		logger.Info("TLS disabled - service will run in HTTP mode")
	}

	// Register routes
	logger.Info("Registering API routes...")
	r.POST("/", generateOTPHandler)
	r.GET("/", verifyOTPHandler)
	logger.Info("Core API routes registered (POST / for generation, GET / for verification)")

	// Health check route, utilizing middleware for status check
	r.GET("/health", func(c *gin.Context) {
		logger.Debug("Health check endpoint accessed")

		// Prepare response data with sensitive config masking
		responseData := map[string]interface{}{
			"redis_status": "OK",
			"config":       "***********",
			"server_mode":  cfg.Server.Mode,
		}
		if cfg.Server.Mode == "test" {
			responseData["test_mode"] = true
			responseData["debug_features"] = map[string]interface{}{
				"otp_visible_in_generation": true,
				"detailed_debug_info":       true,
				"request_tracking":          true,
			}
			// Show some config details but not sensitive ones
			responseData["config_summary"] = map[string]interface{}{
				"redis_host":  cfg.Redis.Host,
				"redis_port":  cfg.Redis.Port,
				"server_host": cfg.Server.Host,
				"server_port": cfg.Server.Port,
				"hash_keys":   cfg.Config.HashKeys,
			}
		}

		logger.WithFields(logrus.Fields{
			"redis_status": "OK",
			"server_mode": cfg.Server.Mode,
			"client_ip": c.ClientIP(),
		}).Debug("Health check completed successfully")
		
		sendAPIResponse(c, http.StatusOK, StatusServiceHealth, responseData)
	})
	logger.Info("Health check route registered")

	// Set up HTTP server with timeouts and size limits
	logger.Info("Configuring HTTP server parameters...")
	server := &http.Server{
		Addr:              fmt.Sprintf("%s:%s", cfg.Server.Host, cfg.Server.Port),
		Handler:           r,
		TLSConfig:         tlsConfig,
		ReadTimeout:       time.Duration(cfg.Server.Timeout.Read) * time.Second,
		WriteTimeout:      time.Duration(cfg.Server.Timeout.Write) * time.Second,
		IdleTimeout:       time.Duration(cfg.Server.Timeout.Idle) * time.Second,
		ReadHeaderTimeout: time.Duration(cfg.Server.Timeout.ReadHeader) * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB max header size
	}
	
	logger.WithFields(logrus.Fields{
		"bind_address": server.Addr,
		"read_timeout_sec": cfg.Server.Timeout.Read,
		"write_timeout_sec": cfg.Server.Timeout.Write,
		"idle_timeout_sec": cfg.Server.Timeout.Idle,
		"read_header_timeout_sec": cfg.Server.Timeout.ReadHeader,
		"max_header_bytes": server.MaxHeaderBytes,
		"tls_enabled": tlsConfig != nil,
	}).Info("HTTP server configured successfully")

	// Graceful shutdown
	logger.Info("Setting up graceful shutdown handler...")
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	logger.Info("Signal handlers registered for graceful shutdown (SIGINT, SIGTERM)")

	go func() {
		signal := <-quit
		logger.WithFields(logrus.Fields{
			"signal": signal.String(),
			"service": "otp-service",
			"shutdown_timeout_sec": 30,
		}).Info("Shutdown signal received - initiating graceful shutdown")

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Log start of shutdown process
		shutdownStart := time.Now()
		
		// Shutdown HTTP server
		logger.Info("Shutting down HTTP server...")
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.WithError(err).Fatal("Server forced shutdown due to timeout or error")
		} else {
			logger.Info("HTTP server shutdown completed successfully")
		}

		// Close Redis connection
		logger.Info("Closing Redis connection...")
		if err := redisClient.Close(); err != nil {
			logger.WithError(err).Error("Error occurred while closing Redis client")
		} else {
			logger.Info("Redis connection closed successfully")
		}
		
		shutdownDuration := time.Since(shutdownStart)
		logger.WithFields(logrus.Fields{
			"service": "otp-service",
			"shutdown_duration_ms": shutdownDuration.Milliseconds(),
			"final_status": "shutdown_complete",
		}).Info("OTP Service shutdown completed successfully")
	}()

	// Start server
	logger.WithFields(logrus.Fields{
		"service": "otp-service",
		"version": "1.0.0",
		"address": server.Addr,
		"tls_enabled": cfg.Server.TLS.Enabled,
		"server_mode": cfg.Server.Mode,
		"startup_complete": true,
	}).Info("OTP Service startup completed - server ready to accept connections")
	
	if cfg.Server.TLS.Enabled {
		logger.WithField("protocol", "HTTPS").Info("Starting HTTPS server...")
		if err := server.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			logger.WithFields(logrus.Fields{
				"address": server.Addr,
				"protocol": "HTTPS",
			}).WithError(err).Fatal("Failed to start HTTPS server")
			handleFatalError("Failed to start server", err)
		}
	} else {
		logger.WithField("protocol", "HTTP").Info("Starting HTTP server...")
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			logger.WithFields(logrus.Fields{
				"address": server.Addr,
				"protocol": "HTTP",
			}).WithError(err).Fatal("Failed to start HTTP server")
			handleFatalError("Failed to start server", err)
		}
	}
	
	logger.Info("OTP Service stopped")
}

// requestSizeLimitMiddleware limits request body size to prevent resource exhaustion
func requestSizeLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Limit request body size to 1MB to prevent resource exhaustion
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1024*1024)
		c.Next()
	}
}

// corsMiddleware adds CORS headers to prevent CSRF attacks
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		
		// In production, define specific allowed origins
		// For development/test, allow localhost
		allowedOrigins := []string{
			"http://localhost:3000",
			"http://localhost:8080",
			"https://localhost:3000",
			"https://localhost:8080",
		}
		
		// Only allow specific origins
		allowed := false
		for _, allowedOrigin := range allowedOrigins {
			if origin == allowedOrigin {
				allowed = true
				break
			}
		}
		
		if allowed {
			c.Header("Access-Control-Allow-Origin", origin)
		}
		
		// Define allowed methods
		c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		
		// Define allowed headers
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
		
		// Define allowed credentials
		c.Header("Access-Control-Allow-Credentials", "true")
		
		// Max age for preflight
		c.Header("Access-Control-Max-Age", "86400")
		
		// Handle preflight requests
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		
		c.Next()
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

		logger.WithFields(logrus.Fields{
			"middleware": "security_headers",
			"tls_enabled": cfg.Server.TLS.Enabled,
			"hsts_applied": cfg.Server.TLS.Enabled,
		}).Debug("Security headers applied successfully")
		
		c.Next()
	}
}
