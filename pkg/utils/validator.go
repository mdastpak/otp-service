// pkg/utils/validator.go

package utils

import (
	"fmt"
	"otp-service/internal/domain"
)

const (
	MinTTL        = 1
	MaxTTL        = 3600 // 1 hour
	MinRetryLimit = 1
	MaxRetryLimit = 60
	MinCodeLength = 1
	MaxCodeLength = 10
)

// ValidateOTPRequest validates the OTP generation request parameters
func ValidateOTPRequest(req *domain.OTPRequest) error {
	if req.TTL < MinTTL || req.TTL > MaxTTL {
		return fmt.Errorf("%w: TTL must be between %d and %d seconds",
			domain.ErrTTLInvalid, MinTTL, MaxTTL)
	}

	if req.RetryLimit < MinRetryLimit || req.RetryLimit > MaxRetryLimit {
		return fmt.Errorf("%w: Retry limit must be between %d and %d",
			domain.ErrRetryInvalid, MinRetryLimit, MaxRetryLimit)
	}

	if req.CodeLength < MinCodeLength || req.CodeLength > MaxCodeLength {
		return fmt.Errorf("%w: Code length must be between %d and %d",
			domain.ErrCodeLengthInvalid, MinCodeLength, MaxCodeLength)
	}

	return nil
}
