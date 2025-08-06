package metrics

import (
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

// Stats represents a snapshot of current metrics
type Stats struct {
	OTPGenerated  int64 `json:"otp_generated"`
	OTPVerified   int64 `json:"otp_verified"`
	OTPExpired    int64 `json:"otp_expired"`
	OTPInvalid    int64 `json:"otp_invalid"`
	RateLimited   int64 `json:"rate_limited"`
	RedisErrors   int64 `json:"redis_errors"`
	TotalRequests int64 `json:"total_requests"`
	StartTime     int64 `json:"start_time"`
}

// Metrics holds application metrics
type Metrics struct {
	OTPGenerated  int64 `json:"otp_generated"`
	OTPVerified   int64 `json:"otp_verified"`
	OTPExpired    int64 `json:"otp_expired"`
	OTPInvalid    int64 `json:"otp_invalid"`
	RateLimited   int64 `json:"rate_limited"`
	RedisErrors   int64 `json:"redis_errors"`
	TotalRequests int64 `json:"total_requests"`
	StartTime     int64 `json:"start_time"`
	logger        *logrus.Logger
}

// NewMetrics creates a new metrics instance
func NewMetrics(logger *logrus.Logger) *Metrics {
	return &Metrics{
		StartTime: time.Now().Unix(),
		logger:    logger,
	}
}

// IncrementOTPGenerated increments the OTP generated counter
func (m *Metrics) IncrementOTPGenerated() {
	atomic.AddInt64(&m.OTPGenerated, 1)
	atomic.AddInt64(&m.TotalRequests, 1)
}

// IncrementOTPVerified increments the OTP verified counter
func (m *Metrics) IncrementOTPVerified() {
	atomic.AddInt64(&m.OTPVerified, 1)
	atomic.AddInt64(&m.TotalRequests, 1)
}

// IncrementOTPExpired increments the OTP expired counter
func (m *Metrics) IncrementOTPExpired() {
	atomic.AddInt64(&m.OTPExpired, 1)
}

// IncrementOTPInvalid increments the OTP invalid counter
func (m *Metrics) IncrementOTPInvalid() {
	atomic.AddInt64(&m.OTPInvalid, 1)
}

// IncrementRateLimited increments the rate limited counter
func (m *Metrics) IncrementRateLimited() {
	atomic.AddInt64(&m.RateLimited, 1)
}

// IncrementRedisErrors increments the Redis errors counter
func (m *Metrics) IncrementRedisErrors() {
	atomic.AddInt64(&m.RedisErrors, 1)
}

// GetStats returns current metrics as Stats struct
func (m *Metrics) GetStats() Stats {
	return Stats{
		OTPGenerated:  atomic.LoadInt64(&m.OTPGenerated),
		OTPVerified:   atomic.LoadInt64(&m.OTPVerified),
		OTPExpired:    atomic.LoadInt64(&m.OTPExpired),
		OTPInvalid:    atomic.LoadInt64(&m.OTPInvalid),
		RateLimited:   atomic.LoadInt64(&m.RateLimited),
		RedisErrors:   atomic.LoadInt64(&m.RedisErrors),
		TotalRequests: atomic.LoadInt64(&m.TotalRequests),
		StartTime:     m.StartTime,
	}
}

// GetStatsMap returns current metrics as map (for backward compatibility)
func (m *Metrics) GetStatsMap() map[string]interface{} {
	uptime := time.Now().Unix() - m.StartTime
	return map[string]interface{}{
		"otp_generated":  atomic.LoadInt64(&m.OTPGenerated),
		"otp_verified":   atomic.LoadInt64(&m.OTPVerified),
		"otp_expired":    atomic.LoadInt64(&m.OTPExpired),
		"otp_invalid":    atomic.LoadInt64(&m.OTPInvalid),
		"rate_limited":   atomic.LoadInt64(&m.RateLimited),
		"redis_errors":   atomic.LoadInt64(&m.RedisErrors),
		"total_requests": atomic.LoadInt64(&m.TotalRequests),
		"uptime_seconds": uptime,
		"start_time":     m.StartTime,
	}
}

// GetUptime returns the uptime duration
func (m *Metrics) GetUptime() time.Duration {
	return time.Since(time.Unix(m.StartTime, 0))
}

// LogMetrics logs current metrics periodically
func (m *Metrics) LogMetrics() {
	stats := m.GetStatsMap()
	m.logger.WithFields(logrus.Fields(stats)).Info("Application metrics")
}
