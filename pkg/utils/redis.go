// pkg/utils/redis.go

package utils

import (
	"crypto/sha256"
	"fmt"
	"strconv"
	"strings"
)

// RedisKeyConfig holds configuration for Redis key generation
type RedisKeyConfig struct {
	HashKeys  bool
	KeyPrefix string
	DB        string
}

// RedisKeyManager handles Redis key generation and sharding
type RedisKeyManager struct {
	config RedisKeyConfig
}

func NewRedisKeyManager(config RedisKeyConfig) *RedisKeyManager {
	return &RedisKeyManager{
		config: config,
	}
}

func (m *RedisKeyManager) GetKey(uuid string) string {
	key := uuid
	if m.config.HashKeys {
		key = m.hashKey(uuid)
	}
	if m.config.KeyPrefix != "" {
		key = fmt.Sprintf("%s:%s", m.config.KeyPrefix, key)
	}
	return key
}

func (m *RedisKeyManager) GetShardIndex(uuid string) (int, error) {
	rangeParts := strings.Split(m.config.DB, "-")

	// Single shard case
	if m.config.DB == "0" {
		return 0, nil
	}

	// Single number case
	if len(rangeParts) == 1 {
		index, err := strconv.Atoi(rangeParts[0])
		if err != nil {
			return 0, fmt.Errorf("invalid DB range configuration: %w", err)
		}
		if index == 0 {
			return 0, nil
		}
		return int(sha256.Sum256([]byte(uuid))[0]) % index, nil
	}

	// Range case
	if len(rangeParts) == 2 {
		start, err := strconv.Atoi(rangeParts[0])
		if err != nil {
			return 0, fmt.Errorf("invalid DB range start: %w", err)
		}
		end, err := strconv.Atoi(rangeParts[1])
		if err != nil {
			return 0, fmt.Errorf("invalid DB range end: %w", err)
		}

		shardRange := end - start + 1
		if shardRange <= 0 {
			return 0, fmt.Errorf("invalid DB range: end must be greater than start")
		}

		shard := int(sha256.Sum256([]byte(uuid))[0]) % shardRange
		return start + shard, nil
	}

	return 0, fmt.Errorf("invalid DB range format")
}

func (m *RedisKeyManager) hashKey(uuid string) string {
	hash := sha256.Sum256([]byte(uuid))
	return fmt.Sprintf("%x", hash)
}
