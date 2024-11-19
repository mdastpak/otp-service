// internal/repository/redis/cached_repository.go

package redis

import (
	"context"
	"fmt"
	"time"

	"otp-service/internal/domain"
	"otp-service/pkg/cache"
	"otp-service/pkg/logger"
	"otp-service/pkg/utils"

	"github.com/go-redis/redis/v8"
)

type CachedOTPRepository struct {
	repo   domain.OTPRepository
	cache  *cache.LocalCache
	client *redis.Client // Add Redis client for debugging
	keyMgr *utils.RedisKeyManager
}

func NewCachedOTPRepository(repo domain.OTPRepository, cache *cache.LocalCache, client *redis.Client, keyMgr *utils.RedisKeyManager) domain.MonitoredRepository {
	return &CachedOTPRepository{
		repo:   repo,
		cache:  cache,
		client: client,
		keyMgr: keyMgr,
	}
}

func (c *CachedOTPRepository) Store(ctx context.Context, otp *domain.OTP) error {
	err := c.repo.Store(ctx, otp)
	if err != nil {
		return err
	}

	// Cache the OTP with TTL
	ttl := time.Duration(otp.TTL) * time.Second
	c.cache.Set(otp.UUID, otp, ttl)

	logger.Debug(fmt.Sprintf("Stored OTP %s in cache", otp.UUID))
	return nil
}

func (c *CachedOTPRepository) Get(ctx context.Context, uuid string) (*domain.OTP, error) {
	// Try cache first
	if cachedOTP, found := c.cache.Get(uuid); found {
		logger.Debug(fmt.Sprintf("Cache hit for OTP %s", uuid))
		return cachedOTP.(*domain.OTP), nil
	}

	// Cache miss, get from Redis
	otp, err := c.repo.Get(ctx, uuid)
	if err != nil {
		return nil, err
	}

	// Cache the result
	ttl := time.Until(otp.ExpiresAt)
	if ttl > 0 {
		c.cache.Set(uuid, otp, ttl)
		logger.Debug(fmt.Sprintf("Cached OTP %s from Redis", uuid))
	}

	return otp, nil
}

func (c *CachedOTPRepository) Update(ctx context.Context, otp *domain.OTP) error {
	err := c.repo.Update(ctx, otp)
	if err != nil {
		return err
	}

	// Update cache
	ttl := time.Until(otp.ExpiresAt)
	if ttl > 0 {
		c.cache.Set(otp.UUID, otp, ttl)
		logger.Debug(fmt.Sprintf("Updated OTP %s in cache", otp.UUID))
	}

	return nil
}

func (c *CachedOTPRepository) Delete(ctx context.Context, uuid string) error {
	err := c.repo.Delete(ctx, uuid)
	if err != nil {
		return err
	}

	// Remove from cache
	c.cache.Delete(uuid)
	logger.Debug(fmt.Sprintf("Deleted OTP %s from cache", uuid))

	return nil
}

func (c *CachedOTPRepository) GetCacheMetrics() *cache.CacheMetrics {
	return c.cache.GetMetrics()
}

// Implement DebugDBDistribution implementation
func (c *CachedOTPRepository) DebugDBDistribution() {
	for i := 0; i <= 5; i++ { // Assuming DB range 0-5
		// Create client for this DB
		client := redis.NewClient(&redis.Options{
			Addr:     c.client.Options().Addr,
			Password: c.client.Options().Password,
			DB:       i,
		})
		defer client.Close()

		// Get pattern for keys
		pattern := c.keyMgr.GetKeyPattern()

		// Get keys for this DB
		keys, err := client.Keys(context.Background(), pattern).Result()
		if err != nil {
			logger.Error(fmt.Sprintf("Failed to get keys from DB %d: %v", i, err))
			continue
		}

		// Log distribution
		logger.Info(fmt.Sprintf("Redis DB %d has %d keys matching pattern %s",
			i, len(keys), pattern))

		// Optional: Log cache hit ratio for this DB
		if len(keys) > 0 {
			cacheHits := 0
			for _, key := range keys {
				if _, found := c.cache.Get(key); found {
					cacheHits++
				}
			}
			hitRatio := float64(cacheHits) / float64(len(keys))
			logger.Info(fmt.Sprintf("DB %d cache hit ratio: %.2f", i, hitRatio))
		}
	}
}

// Implement GetCache method
func (c *CachedOTPRepository) GetCache() *cache.LocalCache {
	return c.cache
}

// Implement GetMetrics method
func (c *CachedOTPRepository) GetMetrics() *cache.CacheMetrics {
	return c.cache.GetMetrics()
}
