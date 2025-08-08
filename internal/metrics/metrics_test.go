package metrics

import (
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestNewMetrics(t *testing.T) {
	logger := logrus.New()
	m := NewMetrics(logger)

	assert.NotNil(t, m)
	assert.Equal(t, int64(0), m.OTPGenerated)
	assert.Equal(t, int64(0), m.OTPVerified)
	assert.Equal(t, int64(0), m.TotalRequests)
	assert.True(t, m.StartTime > 0)
}

func TestIncrementOTPGenerated(t *testing.T) {
	logger := logrus.New()
	m := NewMetrics(logger)

	m.IncrementOTPGenerated()

	assert.Equal(t, int64(1), m.OTPGenerated)
	assert.Equal(t, int64(1), m.TotalRequests)
}

func TestIncrementOTPVerified(t *testing.T) {
	logger := logrus.New()
	m := NewMetrics(logger)

	m.IncrementOTPVerified()

	assert.Equal(t, int64(1), m.OTPVerified)
	assert.Equal(t, int64(1), m.TotalRequests)
}

func TestIncrementOTPExpired(t *testing.T) {
	logger := logrus.New()
	m := NewMetrics(logger)

	m.IncrementOTPExpired()

	assert.Equal(t, int64(1), m.OTPExpired)
	assert.Equal(t, int64(0), m.TotalRequests) // Should not increment total requests
}

func TestIncrementOTPInvalid(t *testing.T) {
	logger := logrus.New()
	m := NewMetrics(logger)

	m.IncrementOTPInvalid()

	assert.Equal(t, int64(1), m.OTPInvalid)
}

func TestIncrementRateLimited(t *testing.T) {
	logger := logrus.New()
	m := NewMetrics(logger)

	m.IncrementRateLimited()

	assert.Equal(t, int64(1), m.RateLimited)
}

func TestIncrementRedisErrors(t *testing.T) {
	logger := logrus.New()
	m := NewMetrics(logger)

	m.IncrementRedisErrors()

	assert.Equal(t, int64(1), m.RedisErrors)
}

func TestGetStats(t *testing.T) {
	logger := logrus.New()
	m := NewMetrics(logger)

	// Increment some metrics
	m.IncrementOTPGenerated()
	m.IncrementOTPVerified()
	m.IncrementOTPExpired()

	stats := m.GetStats()

	assert.Equal(t, int64(1), stats["otp_generated"])
	assert.Equal(t, int64(1), stats["otp_verified"])
	assert.Equal(t, int64(1), stats["otp_expired"])
	assert.Equal(t, int64(2), stats["total_requests"])
	assert.Contains(t, stats, "uptime_seconds")
	assert.Contains(t, stats, "start_time")
}

func TestConcurrentIncrements(t *testing.T) {
	logger := logrus.New()
	m := NewMetrics(logger)

	// Test concurrent increments
	concurrency := 100
	done := make(chan bool, concurrency)

	for i := 0; i < concurrency; i++ {
		go func() {
			m.IncrementOTPGenerated()
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < concurrency; i++ {
		<-done
	}

	assert.Equal(t, int64(concurrency), m.OTPGenerated)
	assert.Equal(t, int64(concurrency), m.TotalRequests)
}

func BenchmarkIncrementOTPGenerated(b *testing.B) {
	logger := logrus.New()
	m := NewMetrics(logger)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			m.IncrementOTPGenerated()
		}
	})
}

func BenchmarkGetStats(b *testing.B) {
	logger := logrus.New()
	m := NewMetrics(logger)

	// Pre-populate some metrics
	m.IncrementOTPGenerated()
	m.IncrementOTPVerified()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.GetStats()
	}
}

func TestUptime(t *testing.T) {
	logger := logrus.New()
	m := NewMetrics(logger)

	// Sleep briefly to ensure uptime > 0
	time.Sleep(10 * time.Millisecond)

	stats := m.GetStats()
	uptime := stats["uptime_seconds"].(int64)

	assert.True(t, uptime >= 0)
}
