// pkg/utils/redis_test.go

package utils

import (
	"fmt"
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
