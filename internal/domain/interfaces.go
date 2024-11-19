// internal/domain/interfaces.go

package domain

import (
	"context"
	"otp-service/pkg/cache"
)

type OTPRepository interface {
	Store(ctx context.Context, otp *OTP) error
	Get(ctx context.Context, uuid string) (*OTP, error)
	Update(ctx context.Context, otp *OTP) error
	Delete(ctx context.Context, uuid string) error
}

type RepositoryMonitor interface {
	DebugDBDistribution()
}

// MonitoredRepository combines both interfaces
type MonitoredRepository interface {
	OTPRepository
	RepositoryMonitor
	GetCache() *cache.LocalCache
	GetMetrics() *cache.CacheMetrics
	DebugDBDistribution()
}
