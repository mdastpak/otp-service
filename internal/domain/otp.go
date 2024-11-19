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
	TTL              int  `form:"ttl,default=60"`
	RetryLimit       int  `form:"retry_limit,default=5"`
	CodeLength       int  `form:"code_length,default=6"`
	StrictValidation bool `form:"strict_validation,default=false"`
	UseAlphaNumeric  bool `form:"use_alpha_numeric,default=false"`
}

// OTPResponse represents the response for OTP operations
type OTPResponse struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
	Info    struct {
		UUID string `json:"uuid,omitempty"`
		OTP  string `json:"otp,omitempty"` // Changed from Code to OTP
	} `json:"info,omitempty"`
}

// TestMode helps to check if we're running in test mode
func IsTestMode(mode string) bool {
	return mode == "test"
}
