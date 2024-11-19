// internal/domain/otp.go

package domain

import (
	"context"
	"encoding/json"
	"time"
)

// OTP represents the OTP entity
type OTPRequest struct {
	TTL              int             `form:"ttl,default=60"`
	RetryLimit       int             `form:"retry_limit,default=5"`
	CodeLength       int             `form:"code_length,default=6"`
	StrictValidation bool            `form:"strict_validation,default=false"`
	UseAlphaNumeric  bool            `form:"use_alpha_numeric,default=false"`
	RawJSON          json.RawMessage `json:"-"` // For storing original JSON when StrictValidation is true
}

type OTP struct {
	UUID             string          `json:"uuid"`
	Code             string          `json:"code"`
	TTL              int             `json:"ttl"`
	RetryLimit       int             `json:"retry_limit"`
	RetryCount       int             `json:"retry_count"`
	StrictValidation bool            `json:"strict_validation"`
	UseAlphaNumeric  bool            `json:"use_alpha_numeric"`
	CreatedAt        time.Time       `json:"created_at"`
	ExpiresAt        time.Time       `json:"expires_at"`
	OriginalJSON     json.RawMessage `json:"original_json,omitempty"` // Original JSON for strict validation
}

// OTPResponse represents the response for OTP operations
type OTPResponseInfo struct {
	UUID string `json:"uuid,omitempty"`
	OTP  string `json:"otp,omitempty"`
}

type OTPResponse struct {
	Status  int             `json:"status"`
	Message string          `json:"message"`
	Info    OTPResponseInfo `json:"info,omitempty"`
}

// TestMode helps to check if we're running in test mode
func IsTestMode(mode string) bool {
	return mode == "debug"
}

type VerifyRequest struct {
	UUID          string          `json:"-"`
	Code          string          `json:"-"`
	StrictRequest json.RawMessage `json:"-"`
}

type OTPService interface {
	Generate(ctx context.Context, req *OTPRequest) (*OTPResponse, error)
	Verify(ctx context.Context, req *VerifyRequest) error
}
