// internal/repository/redis/otp.go

package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"otp-service/internal/domain"
	"otp-service/pkg/logger"
	"otp-service/pkg/utils"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
)

type otpRepository struct {
	client *redis.Client
	keyMgr *utils.RedisKeyManager
}

type otpStorageData struct {
	Code             string          `json:"code"`
	TTL              int             `json:"ttl"`
	RetryLimit       int             `json:"retry_limit"`
	RetryCount       int             `json:"retry_count"`
	StrictValidation bool            `json:"strict_validation"`
	UseAlphaNumeric  bool            `json:"use_alpha_numeric"`
	CreatedAt        time.Time       `json:"created_at"`
	ExpiresAt        time.Time       `json:"expires_at"`
	OriginalJSON     json.RawMessage `json:"original_json,omitempty"` // Added for strict validation
}

func NewOTPRepository(client *redis.Client, keyMgr *utils.RedisKeyManager) domain.MonitoredRepository {
	return &otpRepository{
		client: client,
		keyMgr: keyMgr,
	}
}

// getRedisClient returns a new Redis client for the specified DB
func (r *otpRepository) getRedisClient(dbIndex int) *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:     r.client.Options().Addr,
		Password: r.client.Options().Password,
		DB:       dbIndex,
	})
}

func (r *otpRepository) Store(ctx context.Context, otp *domain.OTP) error {
	dbIndex, err := r.keyMgr.GetShardIndex(otp.UUID)
	if err != nil {
		return fmt.Errorf("failed to get shard index: %w", err)
	}

	// Get client for specific DB
	client := r.getRedisClient(dbIndex)
	defer client.Close()

	key := r.keyMgr.GetKey(otp.UUID)

	// Convert to storage format (excluding UUID)
	storageData := otpStorageData{
		Code:             otp.Code,
		TTL:              otp.TTL,
		RetryLimit:       otp.RetryLimit,
		RetryCount:       otp.RetryCount,
		StrictValidation: otp.StrictValidation,
		UseAlphaNumeric:  otp.UseAlphaNumeric,
		CreatedAt:        otp.CreatedAt,
		ExpiresAt:        otp.ExpiresAt,
		OriginalJSON:     otp.OriginalJSON,
	}

	data, err := json.Marshal(storageData)
	if err != nil {
		return fmt.Errorf("failed to marshal OTP: %w", err)
	}

	ttl := time.Duration(otp.TTL) * time.Second
	if err := client.Set(ctx, key, data, ttl).Err(); err != nil {
		return fmt.Errorf("failed to store OTP in Redis DB %d: %w", dbIndex, err)
	}

	// Debug logging for key transformation
	if logger.GetLogger().Level == logrus.DebugLevel {
		logger.Debug(fmt.Sprintf("Key transformation: \n%s",
			r.keyMgr.DebugKeyTransformation(otp.UUID)))
	}

	logger.Debug(fmt.Sprintf("Stored OTP in Redis DB %d with key %s and JSON: %s",
		dbIndex, key, string(otp.OriginalJSON)))

	return nil
}

func (r *otpRepository) Get(ctx context.Context, uuid string) (*domain.OTP, error) {
	dbIndex, err := r.keyMgr.GetShardIndex(uuid)
	if err != nil {
		return nil, fmt.Errorf("failed to get shard index: %w", err)
	}

	// Get client for specific DB
	client := r.getRedisClient(dbIndex)
	defer client.Close()

	key := r.keyMgr.GetKey(uuid)
	data, err := client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, domain.ErrOTPNotFound
		}
		return nil, fmt.Errorf("failed to get OTP from Redis DB %d: %w", dbIndex, err)
	}

	var storageData otpStorageData
	if err := json.Unmarshal(data, &storageData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal OTP: %w", err)
	}

	// Convert back to domain model
	otp := &domain.OTP{
		UUID:             uuid, // Add back the UUID from the request
		Code:             storageData.Code,
		TTL:              storageData.TTL,
		RetryLimit:       storageData.RetryLimit,
		RetryCount:       storageData.RetryCount,
		StrictValidation: storageData.StrictValidation,
		UseAlphaNumeric:  storageData.UseAlphaNumeric,
		CreatedAt:        storageData.CreatedAt,
		ExpiresAt:        storageData.ExpiresAt,
	}

	logger.Debug(fmt.Sprintf("Retrieved OTP from Redis DB %d with key %s", dbIndex, key))
	return otp, nil
}

func (r *otpRepository) Update(ctx context.Context, otp *domain.OTP) error {
	dbIndex, err := r.keyMgr.GetShardIndex(otp.UUID)
	if err != nil {
		return fmt.Errorf("failed to get shard index: %w", err)
	}

	// Get client for specific DB
	client := r.getRedisClient(dbIndex)
	defer client.Close()

	key := r.keyMgr.GetKey(otp.UUID)

	// Get existing TTL
	ttl, err := client.TTL(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return domain.ErrOTPNotFound
		}
		return fmt.Errorf("failed to get TTL for OTP in Redis DB %d: %w", dbIndex, err)
	}

	// Convert to storage format
	storageData := otpStorageData{
		Code:             otp.Code,
		TTL:              otp.TTL,
		RetryLimit:       otp.RetryLimit,
		RetryCount:       otp.RetryCount,
		StrictValidation: otp.StrictValidation,
		UseAlphaNumeric:  otp.UseAlphaNumeric,
		CreatedAt:        otp.CreatedAt,
		ExpiresAt:        otp.ExpiresAt,
	}

	data, err := json.Marshal(storageData)
	if err != nil {
		return fmt.Errorf("failed to marshal OTP: %w", err)
	}

	// Use existing TTL if it's positive
	if ttl > 0 {
		if err := client.Set(ctx, key, data, ttl).Err(); err != nil {
			return fmt.Errorf("failed to update OTP in Redis DB %d: %w", dbIndex, err)
		}
	} else {
		newTTL := time.Duration(otp.TTL) * time.Second
		if err := client.Set(ctx, key, data, newTTL).Err(); err != nil {
			return fmt.Errorf("failed to update OTP in Redis DB %d: %w", dbIndex, err)
		}
	}

	logger.Debug(fmt.Sprintf("Updated OTP in Redis DB %d with key %s", dbIndex, key))
	return nil
}

func (r *otpRepository) Delete(ctx context.Context, uuid string) error {
	dbIndex, err := r.keyMgr.GetShardIndex(uuid)
	if err != nil {
		return fmt.Errorf("failed to get shard index: %w", err)
	}

	// Get client for specific DB
	client := r.getRedisClient(dbIndex)
	defer client.Close()

	key := r.keyMgr.GetKey(uuid)
	result := client.Del(ctx, key)
	if err := result.Err(); err != nil {
		return fmt.Errorf("failed to delete OTP from Redis DB %d: %w", dbIndex, err)
	}

	if result.Val() == 0 {
		return domain.ErrOTPNotFound
	}

	logger.Debug(fmt.Sprintf("Deleted OTP from Redis DB %d with key %s", dbIndex, key))
	return nil
}

func (r *otpRepository) DebugDBDistribution() {
	for i := 0; i <= 5; i++ {
		client := r.getRedisClient(i)
		defer client.Close()

		keys, err := client.Keys(context.Background(), r.keyMgr.GetKeyPattern()).Result()
		if err != nil {
			logger.Error(fmt.Sprintf("Failed to get keys from DB %d: %v", i, err))
			continue
		}
		logger.Debug(fmt.Sprintf("Redis DB %d has %d keys", i, len(keys)))
	}
}
