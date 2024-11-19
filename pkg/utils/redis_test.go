// pkg/utils/redis_test.go

package utils

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestShardDistribution(t *testing.T) {
	keyMgr := NewRedisKeyManager(RedisKeyConfig{
		DB: "0-5", // Test range 0-5
	})

	// Generate test UUIDs
	numTests := 1000
	uuids := make([]string, numTests)
	for i := 0; i < numTests; i++ {
		uuids[i] = uuid.New().String()
	}

	// Get distribution
	distribution := keyMgr.DebugShardDistribution(uuids)

	// Print distribution
	fmt.Printf("\nShard Distribution for %d keys:\n", numTests)
	for i := 0; i <= 5; i++ {
		count := distribution[i]
		percentage := float64(count) / float64(numTests) * 100
		fmt.Printf("DB %d: %d keys (%.2f%%)\n", i, count, percentage)
	}

	// Check if distribution is reasonably even
	expectedPerShard := numTests / 6             // 6 shards (0-5)
	tolerance := float64(expectedPerShard) * 0.3 // Allow 30% deviation

	for i := 0; i <= 5; i++ {
		count := distribution[i]
		if count == 0 {
			t.Errorf("DB %d has no keys", i)
		}

		deviation := float64(abs(count - expectedPerShard))
		if deviation > tolerance {
			t.Errorf("DB %d distribution is too uneven. Got %d keys, expected around %d (±%.0f)",
				i, count, expectedPerShard, tolerance)
		}
	}
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func TestGetKey(t *testing.T) {
	tests := []struct {
		name     string
		config   RedisKeyConfig
		uuid     string
		expected string
	}{
		{
			name: "with prefix no hash",
			config: RedisKeyConfig{
				KeyPrefix: "otp",
				HashKeys:  false,
			},
			uuid:     "test-uuid",
			expected: "otp:test-uuid",
		},
		{
			name: "with prefix and extra colon",
			config: RedisKeyConfig{
				KeyPrefix: "otp:",
				HashKeys:  false,
			},
			uuid:     "test-uuid",
			expected: "otp:test-uuid",
		},
		{
			name: "with prefix and multiple colons",
			config: RedisKeyConfig{
				KeyPrefix: "otp:::",
				HashKeys:  false,
			},
			uuid:     "test-uuid",
			expected: "otp:test-uuid",
		},
		{
			name: "no prefix no hash",
			config: RedisKeyConfig{
				KeyPrefix: "",
				HashKeys:  false,
			},
			uuid:     "test-uuid",
			expected: "test-uuid",
		},
		{
			name: "with prefix and hash",
			config: RedisKeyConfig{
				KeyPrefix: "otp",
				HashKeys:  true,
			},
			uuid: "test-uuid",
			// expected value will be checked in test
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := NewRedisKeyManager(tt.config)
			result := mgr.GetKey(tt.uuid)

			if tt.config.HashKeys {
				// For hashed keys, verify format
				if !strings.HasPrefix(result, tt.config.KeyPrefix+":") {
					t.Errorf("Expected key to start with %s:, got %s",
						tt.config.KeyPrefix, result)
				}
				// Verify the hash part is 64 characters (SHA-256)
				hashPart := strings.TrimPrefix(result, tt.config.KeyPrefix+":")
				if len(hashPart) != 64 {
					t.Errorf("Expected hash length 64, got %d", len(hashPart))
				}
			} else {
				if result != tt.expected {
					t.Errorf("Expected key %s, got %s", tt.expected, result)
				}
			}
		})
	}
}

func TestGetKeyPattern(t *testing.T) {
	tests := []struct {
		name     string
		config   RedisKeyConfig
		expected string
	}{
		{
			name: "with prefix",
			config: RedisKeyConfig{
				KeyPrefix: "otp",
			},
			expected: "otp:*",
		},
		{
			name: "with prefix and colon",
			config: RedisKeyConfig{
				KeyPrefix: "otp:",
			},
			expected: "otp:*",
		},
		{
			name: "no prefix",
			config: RedisKeyConfig{
				KeyPrefix: "",
			},
			expected: "*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := NewRedisKeyManager(tt.config)
			result := mgr.GetKeyPattern()
			if result != tt.expected {
				t.Errorf("Expected pattern %s, got %s", tt.expected, result)
			}
		})
	}
}
