// internal/domain/interfaces.go

package domain

import "context"

type OTPService interface {
	Generate(ctx context.Context, req *OTPRequest) (*OTPResponse, error)
	Verify(ctx context.Context, uuid string, code string) error
}

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
}
