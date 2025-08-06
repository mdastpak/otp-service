package redis

import "otp-service/internal/models"

// RedisInterface defines the contract for Redis operations
type RedisInterface interface {
	CheckRateLimit(clientID string) bool
	SaveOTP(uuid string, otpData models.OTPRequest) error
	GetOTP(uuid string) (*models.OTPRequest, error)
	DeleteOTP(uuid string) error
	UpdateRetryLimit(uuid string, otpData *models.OTPRequest) error
	Close() error
	Ping() error
}

// Ensure Client implements RedisInterface
var _ RedisInterface = (*Client)(nil)
