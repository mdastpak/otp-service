// internal/domain/otp.go

package domain

import "time"

// OTP represents the OTP entity
type OTP struct {
	UUID             string    `json:"uuid"`
	Code             string    `json:"code"`
	TTL              int       `json:"ttl"`
	RetryLimit       int       `json:"retry_limit"`
	RetryCount       int       `json:"retry_count"`
	StrictValidation bool      `json:"strict_validation"`
	UseAlphaNumeric  bool      `json:"use_alpha_numeric"`
	CreatedAt        time.Time `json:"created_at"`
	ExpiresAt        time.Time `json:"expires_at"`
}

// OTPRequest represents the request for OTP generation
type OTPRequest struct {
	TTL              int  `form:"ttl"`
	RetryLimit       int  `form:"retry_limit"`
	CodeLength       int  `form:"code_length"`
	StrictValidation bool `form:"strict_validation"`
	UseAlphaNumeric  bool `form:"use_alpha_numeric"`
}

// OTPResponse represents the response for OTP operations
type OTPResponse struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
	Info    struct {
		UUID string `json:"uuid,omitempty"`
	} `json:"info,omitempty"`
}
