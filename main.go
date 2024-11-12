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
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var (
	ctx       = context.Background()
	rbClients []*redis.Client
	logger    = logrus.New()
	config    Config
	rrCounter int
)

// Config structure to hold server, redis, and general configurations
type Config struct {
	Redis struct {
		Host      string `mapstructure:"HOST"`
		Port      string `mapstructure:"PORT"`
		Password  string `mapstructure:"PASSWORD"`
		Indices   string `mapstructure:"INDICES"`
		KeyPrefix string `mapstructure:"KEY_PREFIX"`
	} `mapstructure:"REDIS"`
	Server struct {
		Host string `mapstructure:"HOST"`
		Port string `mapstructure:"PORT"`
	} `mapstructure:"SERVER"`
	Config struct {
		HashKeys bool `mapstructure:"HASH_KEYS"`
	} `mapstructure:"CONFIG"`
}

func init() {
	// Initialize logger
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetLevel(logrus.InfoLevel)

	// Read configuration from file
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")

	if err := viper.ReadInConfig(); err != nil {
		logger.Fatalf("Error reading config file: %v", err)
	}
	viper.AutomaticEnv()

	// Bind environment variables to specific keys in the config
	viper.BindEnv("REDIS.HOST", "REDIS_HOST")
	viper.BindEnv("REDIS.PORT", "REDIS_PORT")
	viper.BindEnv("REDIS.PASSWORD", "REDIS_PASSWORD")
	viper.BindEnv("REDIS.KEY_PREFIX", "REDIS_KEY_PREFIX")
	viper.BindEnv("SERVER.HOST", "SERVER_HOST")
	viper.BindEnv("SERVER.PORT", "SERVER_PORT")
	viper.BindEnv("CONFIG.HASH_KEYS", "HASH_KEYS")

	// Unmarshal configuration into Config struct
	if err := viper.Unmarshal(&config); err != nil {
		logger.Fatalf("Unable to decode into struct, %v", err)
	}

	// Initialize Redis clients based on configuration
	if config.Redis.Indices == "" {
		config.Redis.Indices = ""
	}

	indexList := parseRedisIndices(config.Redis.Indices)
	for _, index := range indexList {
		client := redis.NewClient(&redis.Options{
			Addr:     fmt.Sprintf("%s:%s", config.Redis.Host, config.Redis.Port),
			Password: config.Redis.Password,
			DB:       index,
		})
		rbClients = append(rbClients, client)
	}
}

func parseRedisIndices(indices string) []int {
	var indexList []int
	rangeParts := strings.Split(indices, "-")
	if len(rangeParts) == 1 {
		index, err := strconv.Atoi(rangeParts[0])
		if err != nil {
			logger.Fatalf("Invalid REDIS.INDICES configuration: %v", err)
		}
		indexList = append(indexList, index)
	} else if len(rangeParts) == 2 {
		start, err := strconv.Atoi(rangeParts[0])
		if err != nil {
			logger.Fatalf("Invalid REDIS.INDICES configuration: %v", err)
		}
		end, err := strconv.Atoi(rangeParts[1])
		if err != nil {
			logger.Fatalf("Invalid REDIS.INDICES configuration: %v", err)
		}
		for i := start; i <= end; i++ {
			indexList = append(indexList, i)
		}
	} else {
		logger.Fatalf("Invalid REDIS.INDICES format. Use a single number or a range (e.g., '0-2')")
	}
	return indexList
}

// APIResponse defines the standard structure for all API responses
type APIResponse struct {
	Status  int         `json:"status"`
	Message string      `json:"message"`
	Info    interface{} `json:"info,omitempty"` // Info can hold any type of data (e.g., list or object)
}

// OTPRequest structure for storing OTP-related info
type OTPRequest struct {
	OTP              string          `json:"otp"`
	TTL              int             `json:"ttl"`
	RetryLimit       int             `json:"retry_limit"`
	UseAlphaNumeric  bool            `json:"use_alpha_numeric"`
	ExpirationTime   time.Time       `json:"expiration_time"`
	CodeLength       int             `json:"code_length"`
	StrictValidation bool            `json:"strict_validation"`
	UserData         json.RawMessage `json:"user_data,omitempty"`
	RedisIndex       int             `json:"redis_index"`
}

// Helper to send JSON API responses
func sendAPIResponse(c *gin.Context, status int, message string, info interface{}) {
	c.JSON(status, APIResponse{
		Status:  status,
		Message: message,
		Info:    info,
	})
	logger.WithFields(logrus.Fields{
		"status":  status,
		"message": message,
		"info":    info,
	}).Info("API response sent")
}

// Generate OTP code based on length and complexity
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

// Save OTP data to Redis using round-robin algorithm
func saveOTPToRedis(requestUUID string, otpData OTPRequest) error {
	otpJSON, err := json.Marshal(otpData)
	if err != nil {
		logger.Errorf("Error marshaling OTP data: %v", err)
		return err
	}
	ttl := time.Until(otpData.ExpirationTime)
	key := requestUUID
	if config.Config.HashKeys {
		key = generateRedisKey(requestUUID)
	}

	clientIndex := rrCounter % len(rbClients)
	client := rbClients[clientIndex]
	otpData.RedisIndex = clientIndex

	if config.Redis.KeyPrefix != "" {
		key = fmt.Sprintf("%s:%s", config.Redis.KeyPrefix, key)
	}

	if err := client.Set(ctx, key, otpJSON, ttl).Err(); err != nil {
		logger.Errorf("Error saving OTP to Redis: %v", err)
		return err
	}
	rrCounter++
	return nil
}

// Generate a Redis key using a hash-based structure (SHA-256)
func generateRedisKey(requestUUID string) string {
	hash := sha256.Sum256([]byte(requestUUID))
	return hex.EncodeToString(hash[:])
}

// Helper to update retry limit and save to Redis
func updateRetryLimit(client *redis.Client, key string, otpData *OTPRequest) error {
	otpData.RetryLimit--
	otpJSON, err := json.Marshal(otpData)
	if err != nil {
		return err
	}
	return client.Set(ctx, key, otpJSON, time.Until(otpData.ExpirationTime)).Err()
}

// Handle POST request to generate OTP
func generateOTPHandler(c *gin.Context) {
	var otpRequest OTPRequest

	// Read and parse the request body
	bodyBytes, err := c.GetRawData()
	if err != nil {
		sendAPIResponse(c, http.StatusBadRequest, "REQUEST_BODY_INVALID", nil)
		return
	}

	if err := json.Unmarshal(bodyBytes, &otpRequest); err != nil {
		sendAPIResponse(c, http.StatusBadRequest, "JSON_INVALID", nil)
		return
	}
	otpRequest.UserData = json.RawMessage(bodyBytes)

	// Validate and set parameters
	ttl, err := strconv.Atoi(c.DefaultQuery("ttl", "60"))
	if err != nil || ttl < 1 || ttl > 3600 {
		sendAPIResponse(c, http.StatusBadRequest, "TTL_INVALID", nil)
		return
	}
	otpRequest.TTL = ttl

	retryLimit, err := strconv.Atoi(c.DefaultQuery("retry_limit", "5"))
	if err != nil || retryLimit < 1 || retryLimit > 60 {
		sendAPIResponse(c, http.StatusBadRequest, "RETRY_INVALID", nil)
		return
	}
	otpRequest.RetryLimit = retryLimit

	codeLength, err := strconv.Atoi(c.DefaultQuery("code_length", "6"))
	if err != nil || codeLength < 1 || codeLength > 10 {
		sendAPIResponse(c, http.StatusBadRequest, "CODE_INVALID", nil)
		return
	}
	otpRequest.CodeLength = codeLength

	otpRequest.StrictValidation = c.DefaultQuery("strict_validation", "false") == "true"
	otpRequest.UseAlphaNumeric = c.DefaultQuery("use_alpha_numeric", "false") == "true"

	// Generate OTP
	if otpRequest.OTP, err = generateOTP(otpRequest.CodeLength, otpRequest.UseAlphaNumeric); err != nil {
		sendAPIResponse(c, http.StatusInternalServerError, "OTP_GENERATION_FAILED", nil)
		return
	}
	otpRequest.ExpirationTime = time.Now().Add(time.Duration(otpRequest.TTL) * time.Second)

	// Generate UUID and save OTP to Redis
	requestUUID := uuid.New().String()
	if err := saveOTPToRedis(requestUUID, otpRequest); err != nil {
		sendAPIResponse(c, http.StatusInternalServerError, "REDIS_UNAVAILABLE", nil)
		return
	}

	// Send response with generated UUID
	sendAPIResponse(c, http.StatusOK, "OTP_GENERATED", map[string]string{
		"uuid": requestUUID,
	})
}

// Handle GET request to verify OTP
func verifyOTPHandler(c *gin.Context) {
	requestUUID := c.Param("uuid")
	userInputOTP := c.Param("otp")

	// Validate input
	if requestUUID == "" || userInputOTP == "" {
		sendAPIResponse(c, http.StatusBadRequest, "OTP_MISSING", nil)
		return
	}

	// Generate the Redis key
	key := requestUUID
	if config.Config.HashKeys {
		key = generateRedisKey(requestUUID)
	}

	// Fetch OTP from Redis
	var otpData OTPRequest
	var client *redis.Client
	for _, client = range rbClients {
		storedData, err := client.Get(ctx, key).Result()
		if err == redis.Nil {
			sendAPIResponse(c, http.StatusServiceUnavailable, "REDIS_UNAVAILABLE", nil)
			return
		} else if err != nil {
			sendAPIResponse(c, http.StatusInternalServerError, "REDIS_ERROR", nil)
			return
		}
		if err := json.Unmarshal([]byte(storedData), &otpData); err != nil {
			sendAPIResponse(c, http.StatusInternalServerError, "OTP_INVALID", nil)
			return
		}
		break
	}

	// Check if OTP is found
	if otpData.OTP == "" {
		sendAPIResponse(c, http.StatusUnauthorized, "OTP_EXPIRED", nil)
		return
	}

	// Check retry limit
	if otpData.RetryLimit <= 0 {
		client.Del(ctx, key)
		sendAPIResponse(c, http.StatusUnauthorized, "OTP_ATTEMPTS", nil)
		return
	}

	// Check OTP case-insensitively if alphanumeric
	if !strings.EqualFold(otpData.OTP, userInputOTP) {
		if err := updateRetryLimit(client, key, &otpData); err != nil {
			sendAPIResponse(c, http.StatusInternalServerError, "OTP_INVALID", nil)
			return
		}
		sendAPIResponse(c, http.StatusUnauthorized, "OTP_INVALID", nil)
		return
	}

	// Full body validation, if strict validation is enabled
	if otpData.StrictValidation {
		var currentData map[string]interface{}
		if err := c.ShouldBindJSON(&currentData); err != nil {
			sendAPIResponse(c, http.StatusBadRequest, "REQUEST_BODY_INVALID", nil)
			return
		}

		var storedDataMap map[string]interface{}
		if err := json.Unmarshal(otpData.UserData, &storedDataMap); err != nil {
			sendAPIResponse(c, http.StatusInternalServerError, "OTP_INVALID", nil)
			return
		}

		if !reflect.DeepEqual(storedDataMap, currentData) {
			if err := updateRetryLimit(client, key, &otpData); err != nil {
				sendAPIResponse(c, http.StatusInternalServerError, "OTP_INVALID", nil)
				return
			}
			sendAPIResponse(c, http.StatusUnauthorized, "REQUEST_MISMATCH", nil)
			return
		}
	}

	// OTP verified successfully, delete it from Redis
	client.Del(ctx, key)
	sendAPIResponse(c, http.StatusOK, "OTP_VERIFIED", nil)
}

func main() {
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	r.Use(gin.Logger())

	// Register routes
	r.POST("/", generateOTPHandler)
	r.GET("/:uuid/:otp", verifyOTPHandler)

	r.GET("/health", func(c *gin.Context) {
		// Check Redis health
		healthStatus := "OK"
		for _, client := range rbClients {
			if _, err := client.Ping(ctx).Result(); err != nil {
				healthStatus = "Unavailable"
				break
			}
		}
		sendAPIResponse(c, http.StatusOK, "SERVICE_HEALTH", map[string]string{
			"redis_status": healthStatus,
		})
	})

	serverAddress := fmt.Sprintf("%s:%s", config.Server.Host, config.Server.Port)
	logger.Infof("Server started at %s", serverAddress)
	r.Run(serverAddress)
}
