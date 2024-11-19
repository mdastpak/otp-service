// pkg/metrics/collector.go

package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	RequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "otp_service",
			Name:      "request_duration_seconds",
			Help:      "Time taken to process request",
			Buckets:   []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		},
		[]string{"method", "endpoint", "status"},
	)

	RedisOperationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "otp_service",
			Name:      "redis_operation_duration_seconds",
			Help:      "Time taken for Redis operations",
			Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5},
		},
		[]string{"operation", "db"},
	)

	OTPGenerationTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "otp_service",
			Name:      "generation_total",
			Help:      "Total number of OTPs generated",
		},
		[]string{"status"},
	)

	OTPVerificationTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "otp_service",
			Name:      "verification_total",
			Help:      "Total number of OTP verifications",
		},
		[]string{"status"},
	)

	RedisConnectionStatus = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "otp_service",
			Name:      "redis_connection_status",
			Help:      "Current Redis connection status (1 for connected, 0 for disconnected)",
		},
	)

	ActiveOTPsGauge = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "otp_service",
			Name:      "active_otps",
			Help:      "Number of currently active OTPs",
		},
		[]string{"db"},
	)

	CacheHits = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: "otp_service",
			Name:      "cache_hits_total",
			Help:      "Total number of cache hits",
		},
	)

	CacheMisses = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: "otp_service",
			Name:      "cache_misses_total",
			Help:      "Total number of cache misses",
		},
	)

	CacheEvictions = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: "otp_service",
			Name:      "cache_evictions_total",
			Help:      "Total number of cache evictions",
		},
	)
)

// RecordRedisOperation records the duration of a Redis operation
func RecordRedisOperation(operation string, db string, start time.Time) {
	duration := time.Since(start).Seconds()
	RedisOperationDuration.WithLabelValues(operation, db).Observe(duration)
}

// RecordRequest records the duration of an HTTP request
func RecordRequest(method, endpoint string, status int, start time.Time) {
	duration := time.Since(start).Seconds()
	RequestDuration.WithLabelValues(method, endpoint, string(rune(status))).Observe(duration)
}

// RecordOTPGeneration records an OTP generation attempt
func RecordOTPGeneration(success bool) {
	status := "success"
	if !success {
		status = "failure"
	}
	OTPGenerationTotal.WithLabelValues(status).Inc()
}

// RecordOTPVerification records an OTP verification attempt
func RecordOTPVerification(success bool) {
	status := "success"
	if !success {
		status = "failure"
	}
	OTPVerificationTotal.WithLabelValues(status).Inc()
}

// UpdateRedisConnectionStatus updates the Redis connection status
func UpdateRedisConnectionStatus(connected bool) {
	if connected {
		RedisConnectionStatus.Set(1)
	} else {
		RedisConnectionStatus.Set(0)
	}
}

// UpdateActiveOTPs updates the count of active OTPs
func UpdateActiveOTPs(db string, count int) {
	ActiveOTPsGauge.WithLabelValues(db).Set(float64(count))
}
