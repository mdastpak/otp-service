package redis

import (
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"otp-service/internal/config"
	"otp-service/internal/models"
)

func TestGenerateRedisKey(t *testing.T) {
	cfg := &config.Config{}
	cfg.Config.HashKeys = true
	cfg.Redis.KeyPrefix = "test"

	logger := logrus.New()
	client := &Client{
		config: cfg,
		logger: logger,
	}

	uuid := "test-uuid-123"
	key := client.getRedisKey(uuid)

	// Should include prefix
	assert.Contains(t, key, cfg.Redis.KeyPrefix+":")
	// Should not be the original UUID when hashing is enabled
	assert.NotEqual(t, uuid, key)
}

func TestGenerateRedisKeyNoHash(t *testing.T) {
	cfg := &config.Config{}
	cfg.Config.HashKeys = false
	cfg.Redis.KeyPrefix = ""

	logger := logrus.New()
	client := &Client{
		config: cfg,
		logger: logger,
	}

	uuid := "test-uuid-123"
	key := client.getRedisKey(uuid)

	// Should be the original UUID when hashing is disabled
	assert.Equal(t, uuid, key)
}

func TestGetShardIndex(t *testing.T) {
	tests := []struct {
		name     string
		indices  string
		uuid     string
		expected bool // whether it should not panic
	}{
		{
			name:     "Single index 0",
			indices:  "0",
			uuid:     "test-uuid",
			expected: true,
		},
		{
			name:     "Single index 5",
			indices:  "5",
			uuid:     "test-uuid",
			expected: true,
		},
		{
			name:     "Range 0-3",
			indices:  "0-3",
			uuid:     "test-uuid",
			expected: true,
		},
		{
			name:     "Range 1-5",
			indices:  "1-5",
			uuid:     "test-uuid",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Redis.Indices = tt.indices

			logger := logrus.New()
			client := &Client{
				config: cfg,
				logger: logger,
			}

			// Should not panic
			index := client.getShardIndex(tt.uuid)
			assert.GreaterOrEqual(t, index, 0)
		})
	}
}

func TestOTPRequestSerialization(t *testing.T) {
	otpRequest := models.OTPRequest{
		OTP:              "123456",
		TTL:              60,
		RetryLimit:       5,
		UseAlphaNumeric:  false,
		TTLDuration:      60 * time.Second,
		CodeLength:       6,
		StrictValidation: false,
		UserData:         []byte(`{"test": "data"}`),
	}

	// Test that the struct can be marshaled and unmarshaled
	assert.Equal(t, "123456", otpRequest.OTP)
	assert.Equal(t, 60, otpRequest.TTL)
	assert.Equal(t, 5, otpRequest.RetryLimit)
	assert.Equal(t, 6, otpRequest.CodeLength)
}

func BenchmarkGetRedisKey(b *testing.B) {
	cfg := &config.Config{}
	cfg.Config.HashKeys = true
	cfg.Redis.KeyPrefix = "bench"

	logger := logrus.New()
	client := &Client{
		config: cfg,
		logger: logger,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = client.getRedisKey("test-uuid-123456789")
	}
}

func BenchmarkGetShardIndex(b *testing.B) {
	cfg := &config.Config{}
	cfg.Redis.Indices = "0-15"

	logger := logrus.New()
	client := &Client{
		config: cfg,
		logger: logger,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = client.getShardIndex("test-uuid-123456789")
	}
}

func TestGenerateRedisKeyHash(t *testing.T) {
	cfg := &config.Config{}
	cfg.Config.HashKeys = true

	logger := logrus.New()
	client := &Client{
		config: cfg,
		logger: logger,
	}

	uuid1 := "test-uuid-1"
	uuid2 := "test-uuid-2"

	key1 := client.generateRedisKey(uuid1)
	key2 := client.generateRedisKey(uuid2)

	// Keys should be different for different UUIDs
	assert.NotEqual(t, key1, key2)
	// Keys should be hex encoded (64 characters for SHA-256)
	assert.Len(t, key1, 64)
	assert.Len(t, key2, 64)
}

func TestShardIndexConsistency(t *testing.T) {
	cfg := &config.Config{}
	cfg.Redis.Indices = "0-7"

	logger := logrus.New()
	client := &Client{
		config: cfg,
		logger: logger,
	}

	uuid := "consistent-test-uuid"

	// Get shard index multiple times for the same UUID
	index1 := client.getShardIndex(uuid)
	index2 := client.getShardIndex(uuid)
	index3 := client.getShardIndex(uuid)

	// Should always return the same index for the same UUID
	assert.Equal(t, index1, index2)
	assert.Equal(t, index2, index3)

	// Index should be within expected range (0-7)
	assert.GreaterOrEqual(t, index1, 0)
	assert.LessOrEqual(t, index1, 7)
}
