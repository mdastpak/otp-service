// internal/domain/interfaces.go

package domain

import "context"

// OTPService defines the interface for OTP business logic
type OTPService interface {
	Generate(ctx context.Context, req *OTPRequest) (*OTPResponse, error)
	Verify(ctx context.Context, uuid string, code string) error
}

// OTPRepository defines the interface for OTP data storage
type OTPRepository interface {
	Store(ctx context.Context, otp *OTP) error
	Get(ctx context.Context, uuid string) (*OTP, error)
	Update(ctx context.Context, otp *OTP) error
	Delete(ctx context.Context, uuid string) error
}
