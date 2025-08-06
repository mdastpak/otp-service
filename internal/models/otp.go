package models

import (
	"encoding/json"
	"time"
)

// APIResponse defines the standard structure for all API responses
type APIResponse struct {
	Status  int         `json:"status"`
	Message string      `json:"message"`
	Info    interface{} `json:"info,omitempty"`
}

// OTPRequest structure for storing OTP-related info
type OTPRequest struct {
	OTP              string          `json:"otp"`
	TTL              int             `json:"ttl"`
	RetryLimit       int             `json:"retry_limit"`
	UseAlphaNumeric  bool            `json:"use_alpha_numeric"`
	TTLDuration      time.Duration   `json:"ttl_duration"`
	CodeLength       int             `json:"code_length"`
	StrictValidation bool            `json:"strict_validation"`
	UserData         json.RawMessage `json:"user_data,omitempty"`
}

// Status constants
const (
	StatusOTPGenerated      = "OTP_GENERATED"
	StatusOTPExpired        = "OTP_EXPIRED"
	StatusOTPInvalid        = "OTP_INVALID"
	StatusOTPVerified       = "OTP_VERIFIED"
	StatusOTPMissing        = "OTP_MISSING"
	StatusOTPLimitReached   = "OTP_ATTEMPTS"
	StatusRequestMismatch   = "REQUEST_BODY_MISMATCH"
	StatusTTLInvalid        = "TTL_INVALID"
	StatusRetryInvalid      = "RETRY_INVALID"
	StatusCodeInvalid       = "CODE_LENGTH_INVALID"
	StatusRequestInvalid    = "REQUEST_BODY_INVALID"
	StatusServiceHealth     = "SERVICE_HEALTH"
	StatusRedisUnavailable  = "REDIS_UNAVAILABLE"
	StatusRateLimitExceeded = "RATE_LIMIT_EXCEEDED"
)
