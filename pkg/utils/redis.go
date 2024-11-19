// pkg/utils/redis.go

package utils

import (
	"crypto/sha256"
	"fmt"
	"hash/fnv"
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
			return 0, fmt.Errorf("invalid DB configuration: %w", err)
		}
		if index == 0 {
			return 0, nil
		}
		return getHashedIndex(uuid, 0, index-1), nil
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

		if start > end {
			return 0, fmt.Errorf("invalid DB range: start must be less than end")
		}

		return getHashedIndex(uuid, start, end), nil
	}

	return 0, fmt.Errorf("invalid DB range format")
}

// getHashedIndex generates a consistent hash for UUID within the given range
func getHashedIndex(uuid string, min, max int) int {
	h := fnv.New32a()
	h.Write([]byte(uuid))
	hash := h.Sum32()

	// Calculate range size
	rangeSize := max - min + 1

	// Use modulo to get index within range and add minimum
	index := int(hash%uint32(rangeSize)) + min

	return index
}

// For debugging purposes
func (m *RedisKeyManager) DebugShardDistribution(uuids []string) map[int]int {
	distribution := make(map[int]int)

	for _, uuid := range uuids {
		index, err := m.GetShardIndex(uuid)
		if err == nil {
			distribution[index]++
		}
	}

	return distribution
}

func (m *RedisKeyManager) hashKey(uuid string) string {
	hash := sha256.Sum256([]byte(uuid))
	return fmt.Sprintf("%x", hash)
}

func (m *RedisKeyManager) GetKeyPattern() string {
	if m.config.KeyPrefix != "" {
		return fmt.Sprintf("%s:*", m.config.KeyPrefix)
	}
	return "*"
}
