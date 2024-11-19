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
)

type otpRepository struct {
	client *redis.Client
	keyMgr *utils.RedisKeyManager
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
	// Get DB index for this UUID
	dbIndex, err := r.keyMgr.GetShardIndex(otp.UUID)
	if err != nil {
		return fmt.Errorf("failed to get shard index: %w", err)
	}

	// Get client for specific DB
	client := r.getRedisClient(dbIndex)
	defer client.Close()

	key := r.keyMgr.GetKey(otp.UUID)
	data, err := json.Marshal(otp)
	if err != nil {
		return fmt.Errorf("failed to marshal OTP: %w", err)
	}

	ttl := time.Duration(otp.TTL) * time.Second
	if err := client.Set(ctx, key, data, ttl).Err(); err != nil {
		return fmt.Errorf("failed to store OTP in Redis DB %d: %w", dbIndex, err)
	}

	logger.Debug(fmt.Sprintf("Stored OTP in Redis DB %d with key %s", dbIndex, key))
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

	var otp domain.OTP
	if err := json.Unmarshal(data, &otp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal OTP: %w", err)
	}

	logger.Debug(fmt.Sprintf("Retrieved OTP from Redis DB %d with key %s", dbIndex, key))
	return &otp, nil
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

	data, err := json.Marshal(otp)
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
