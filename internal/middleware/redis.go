// internal/middleware/redis.go

package middleware

import (
	"otp-service/internal/domain"
	"otp-service/pkg/logger"
	"time"
)

// MonitorRedisDistribution monitors Redis key distribution periodically
func MonitorRedisDistribution(monitor domain.RepositoryMonitor) {
	logger.Info("Starting Redis distribution monitoring")
	ticker := time.NewTicker(1 * time.Minute)
	go func() {
		for range ticker.C {
			monitor.DebugDBDistribution()
		}
	}()
}
