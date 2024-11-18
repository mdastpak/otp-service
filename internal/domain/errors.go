// internal/domain/errors.go

package domain

import "errors"

// Repository errors
var (
	ErrOTPNotFound      = errors.New("OTP_NOT_FOUND")
	ErrRedisUnavailable = errors.New("REDIS_UNAVAILABLE")
)

// Validation errors
var (
	ErrInvalidRequest      = errors.New("REQUEST_BODY_INVALID")
	ErrMissingParameters   = errors.New("OTP_MISSING")
	ErrTTLInvalid          = errors.New("TTL_INVALID")
	ErrRetryInvalid        = errors.New("RETRY_INVALID")
	ErrCodeLengthInvalid   = errors.New("CODE_LENGTH_INVALID")
	ErrRequestBodyMismatch = errors.New("REQUEST_BODY_MISMATCH")
)

// Business logic errors
var (
	ErrOTPExpired  = errors.New("OTP_EXPIRED")
	ErrOTPInvalid  = errors.New("OTP_INVALID")
	ErrOTPAttempts = errors.New("OTP_ATTEMPTS")
)

// Rate limiting errors
var (
	ErrRateLimitExceeded = errors.New("RATE_LIMIT_EXCEEDED")
)

// IsNotFound checks if the error is a not found error
func IsNotFound(err error) bool {
	return errors.Is(err, ErrOTPNotFound)
}

// IsValidationError checks if the error is a validation error
func IsValidationError(err error) bool {
	return errors.Is(err, ErrInvalidRequest) ||
		errors.Is(err, ErrMissingParameters) ||
		errors.Is(err, ErrTTLInvalid) ||
		errors.Is(err, ErrRetryInvalid) ||
		errors.Is(err, ErrCodeLengthInvalid) ||
		errors.Is(err, ErrRequestBodyMismatch)
}

// IsBusinessError checks if the error is a business logic error
func IsBusinessError(err error) bool {
	return errors.Is(err, ErrOTPExpired) ||
		errors.Is(err, ErrOTPInvalid) ||
		errors.Is(err, ErrOTPAttempts)
}

// IsInfrastructureError checks if the error is an infrastructure error
func IsInfrastructureError(err error) bool {
	return errors.Is(err, ErrRedisUnavailable)
}

// Error messages for human readable output
var ErrorMessages = map[string]string{
	"OTP_NOT_FOUND":         "OTP not found",
	"REDIS_UNAVAILABLE":     "Redis service is unavailable",
	"REQUEST_BODY_INVALID":  "Invalid request body",
	"OTP_MISSING":           "UUID or OTP code is missing",
	"TTL_INVALID":           "Invalid TTL value (must be between 1 and 3600 seconds)",
	"RETRY_INVALID":         "Invalid retry limit (must be between 1 and 60)",
	"CODE_LENGTH_INVALID":   "Invalid code length (must be between 1 and 10)",
	"REQUEST_BODY_MISMATCH": "Request body validation failed",
	"OTP_EXPIRED":           "OTP has expired",
	"OTP_INVALID":           "Invalid OTP code",
	"OTP_ATTEMPTS":          "Maximum retry attempts reached",
	"RATE_LIMIT_EXCEEDED":   "Rate limit exceeded, please try again later",
}
