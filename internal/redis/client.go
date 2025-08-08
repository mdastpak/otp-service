package redis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"

	"otp-service/internal/config"
	"otp-service/internal/models"
)

// ShardConfig caches parsed shard configuration for performance
type ShardConfig struct {
	shardCount int
	startIndex int
	isRange    bool
}

type Client struct {
	client      *redis.Client
	config      *config.Config
	logger      *logrus.Logger
	ctx         context.Context
	shardConfig *ShardConfig
}

// NewClient creates a new Redis client with connection pooling
func NewClient(cfg *config.Config, logger *logrus.Logger) (*Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr:            fmt.Sprintf("%s:%s", cfg.Redis.Host, cfg.Redis.Port),
		Password:        cfg.Redis.Password,
		ReadTimeout:     time.Duration(cfg.Redis.Timeout) * time.Second,
		WriteTimeout:    time.Duration(cfg.Redis.Timeout) * time.Second,
		PoolSize:        20,
		MinIdleConns:    5,
		MaxRetries:      3,
		DialTimeout:     time.Duration(cfg.Redis.Timeout) * time.Second,
		ConnMaxIdleTime: 5 * time.Minute,
	})

	ctx := context.Background()
	testCtx, cancel := context.WithTimeout(ctx, time.Duration(cfg.Redis.Timeout)*time.Second)
	defer cancel()

	_, err := client.Ping(testCtx).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %v", err)
	}

	logger.Info("Connected to Redis successfully")

	// Initialize shard configuration
	shardConfig, err := initShardConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize shard configuration: %v", err)
	}

	return &Client{
		client:      client,
		config:      cfg,
		logger:      logger,
		ctx:         ctx,
		shardConfig: shardConfig,
	}, nil
}

// Close closes the Redis connection
func (c *Client) Close() error {
	return c.client.Close()
}

// Ping checks Redis connectivity
func (c *Client) Ping() error {
	testCtx, cancel := context.WithTimeout(c.ctx, 2*time.Second)
	defer cancel()
	_, err := c.client.Ping(testCtx).Result()
	return err
}

// initShardConfig parses and caches shard configuration for performance
func initShardConfig(cfg *config.Config) (*ShardConfig, error) {
	rangeParts := strings.Split(cfg.Redis.Indices, "-")

	if cfg.Redis.Indices == "0" {
		return &ShardConfig{shardCount: 1, startIndex: 0, isRange: false}, nil
	}

	if len(rangeParts) == 1 {
		count, err := strconv.Atoi(rangeParts[0])
		if err != nil || count <= 0 {
			return nil, fmt.Errorf("invalid Redis Indices configuration: %v", err)
		}
		return &ShardConfig{shardCount: count, startIndex: 0, isRange: false}, nil
	} else if len(rangeParts) == 2 {
		start, err := strconv.Atoi(rangeParts[0])
		if err != nil {
			return nil, fmt.Errorf("invalid Redis Indices start configuration: %v", err)
		}
		end, err := strconv.Atoi(rangeParts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid Redis Indices end configuration: %v", err)
		}
		count := end - start + 1
		if count <= 0 {
			return nil, fmt.Errorf("invalid Redis Indices configuration: range results in zero or negative count")
		}
		return &ShardConfig{shardCount: count, startIndex: start, isRange: true}, nil
	} else {
		return nil, fmt.Errorf("invalid Redis Indices format. Use a single number or a range (e.g., '0-2')")
	}
}

// generateRedisKey generates a Redis key using SHA-256 hash of the request UUID
func (c *Client) generateRedisKey(requestUUID string) string {
	hash := sha256.Sum256([]byte(requestUUID))
	return hex.EncodeToString(hash[:])
}

// getRedisKey generates the final Redis key using the configuration settings
func (c *Client) getRedisKey(uuid string) string {
	key := uuid
	if c.config.Config.HashKeys {
		key = c.generateRedisKey(uuid)
	}
	if c.config.Redis.KeyPrefix != "" {
		key = fmt.Sprintf("%s:%s", c.config.Redis.KeyPrefix, key)
	}
	return key
}

// getShardIndex determines the appropriate Redis shard index based on UUID
// Uses UUID's inherent randomness for fast, well-distributed sharding
func (c *Client) getShardIndex(uuid string) int {
	if c.shardConfig.shardCount == 1 {
		return c.shardConfig.startIndex
	}

	// Use last 8 hex chars (4 bytes) of UUID for good distribution
	// UUIDs are designed to be random, so this provides excellent distribution
	cleaned := strings.ReplaceAll(uuid, "-", "")
	if len(cleaned) < 8 {
		// Fallback for malformed UUIDs
		return c.shardConfig.startIndex
	}

	lastBytes := cleaned[len(cleaned)-8:] // Last 4 bytes as hex string

	// Convert hex to uint32 for modulo operation
	hash, err := strconv.ParseUint(lastBytes, 16, 32)
	if err != nil {
		// Fallback for parse errors
		return c.shardConfig.startIndex
	}

	// Safe conversion: hash is guaranteed to fit in uint32, then convert to int
	shardOffset := int(uint32(hash)) % c.shardConfig.shardCount
	return c.shardConfig.startIndex + shardOffset
}

// SaveOTP saves the OTP data to Redis under the appropriate shard
func (c *Client) SaveOTP(uuid string, otpData models.OTPRequest) error {
	if otpData.UserData == nil {
		rawData, err := json.Marshal(otpData)
		if err != nil {
			return fmt.Errorf("error marshaling OTP data: %v", err)
		}
		otpData.UserData = json.RawMessage(rawData)
	}
	key := c.getRedisKey(uuid)

	otpJSON, err := json.Marshal(otpData)
	if err != nil {
		return fmt.Errorf("error marshaling OTP data: %v", err)
	}

	saveCtx, cancel := context.WithTimeout(c.ctx, 2*time.Second)
	defer cancel()

	shardIndex := c.getShardIndex(uuid)
	if err := c.client.Do(saveCtx, "SELECT", shardIndex).Err(); err != nil {
		return fmt.Errorf("error selecting Redis index: %v", err)
	}

	if err := c.client.Set(saveCtx, key, otpJSON, otpData.TTLDuration).Err(); err != nil {
		return fmt.Errorf("error saving OTP to Redis: %v", err)
	}
	return nil
}

// GetOTP retrieves the OTP data from Redis using the appropriate shard
func (c *Client) GetOTP(uuid string) (*models.OTPRequest, error) {
	key := c.getRedisKey(uuid)

	retrieveCtx, cancel := context.WithTimeout(c.ctx, 2*time.Second)
	defer cancel()

	shardIndex := c.getShardIndex(uuid)
	if err := c.client.Do(retrieveCtx, "SELECT", shardIndex).Err(); err != nil {
		return nil, fmt.Errorf("error selecting Redis index: %v", err)
	}

	result, err := c.client.Get(retrieveCtx, key).Result()
	if err == redis.Nil {
		return nil, fmt.Errorf(models.StatusOTPExpired)
	} else if err != nil {
		return nil, fmt.Errorf("error retrieving OTP from Redis: %v", err)
	}

	var otpData models.OTPRequest
	if err := json.Unmarshal([]byte(result), &otpData); err != nil {
		return nil, fmt.Errorf("error unmarshaling OTP data: %v", err)
	}
	return &otpData, nil
}

// DeleteOTP deletes the OTP data from Redis under the appropriate shard
func (c *Client) DeleteOTP(uuid string) error {
	key := c.getRedisKey(uuid)

	deleteCtx, cancel := context.WithTimeout(c.ctx, 2*time.Second)
	defer cancel()

	shardIndex := c.getShardIndex(uuid)
	if err := c.client.Do(deleteCtx, "SELECT", shardIndex).Err(); err != nil {
		return fmt.Errorf("error selecting Redis index: %v", err)
	}

	if err := c.client.Del(deleteCtx, key).Err(); err != nil {
		return fmt.Errorf("error deleting OTP from Redis: %v", err)
	}
	return nil
}

// UpdateRetryLimit updates the retry limit for an OTP in Redis without resetting the TTL
func (c *Client) UpdateRetryLimit(uuid string, otpData *models.OTPRequest) error {
	otpData.RetryLimit--

	retrieveCtx, cancel := context.WithTimeout(c.ctx, 2*time.Second)
	defer cancel()
	shardIndex := c.getShardIndex(uuid)
	if err := c.client.Do(retrieveCtx, "SELECT", shardIndex).Err(); err != nil {
		c.logger.Errorf("error selecting Redis index: %v", err)
		return fmt.Errorf("error selecting Redis index: %v", err)
	}
	ttl, err := c.client.TTL(retrieveCtx, c.getRedisKey(uuid)).Result()
	if err != nil {
		c.logger.Errorf("error retrieving TTL from Redis: %v", err)
		return fmt.Errorf("error retrieving TTL from Redis: %v", err)
	}

	otpJSON, err := json.Marshal(otpData)
	if err != nil {
		c.logger.Errorf("error marshaling OTP data: %v", err)
		return fmt.Errorf("error marshaling OTP data: %v", err)
	}

	if err := c.client.Set(retrieveCtx, c.getRedisKey(uuid), otpJSON, ttl).Err(); err != nil {
		c.logger.Errorf("error saving updated OTP to Redis: %v", err)
		return fmt.Errorf("error saving updated OTP to Redis: %v", err)
	}
	c.logger.Infof("Successfully updated RetryLimit for UUID: %s", uuid)
	return nil
}

// CheckRateLimit checks if a client is being rate limited using pipelining
func (c *Client) CheckRateLimit(clientID string) bool {
	redisKey := fmt.Sprintf("rate_limit:%s", clientID)
	limiterCtx, cancel := context.WithTimeout(c.ctx, 2*time.Second)
	defer cancel()

	// Use pipeline for atomic operations
	pipe := c.client.Pipeline()
	incrCmd := pipe.Incr(limiterCtx, redisKey)
	pipe.Expire(limiterCtx, redisKey, time.Minute)

	_, err := pipe.Exec(limiterCtx)
	if err != nil {
		c.logger.Errorf("Rate limit check failed: %v", err)
		return false
	}

	count := incrCmd.Val()
	// Allow up to 10 requests per minute
	return count > 10
}
