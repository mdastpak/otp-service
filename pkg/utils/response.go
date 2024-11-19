// pkg/utils/response.go

package utils

import (
	"net/http"
	"otp-service/pkg/logger"
	"time"

	"github.com/gin-gonic/gin"
)

// APIError represents a standard error response
type APIError struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
	Code    string `json:"code,omitempty"`
}

// StandardResponse represents a standard success response
type StandardResponse struct {
	Status  int         `json:"status"`
	Message string      `json:"message"`
	Info    interface{} `json:"info,omitempty"`
}

// ErrorResponse maps common errors to HTTP status codes and messages
var ErrorResponse = map[string]APIError{
	"OTP_EXPIRED": {
		Status:  http.StatusBadRequest,
		Message: "OTP has expired",
		Code:    "OTP_EXPIRED",
	},
	"OTP_INVALID": {
		Status:  http.StatusBadRequest,
		Message: "Invalid OTP provided",
		Code:    "OTP_INVALID",
	},
	"OTP_MISSING": {
		Status:  http.StatusBadRequest,
		Message: "UUID or OTP is missing",
		Code:    "OTP_MISSING",
	},
	"OTP_ATTEMPTS": {
		Status:  http.StatusTooManyRequests,
		Message: "Maximum attempts reached",
		Code:    "OTP_ATTEMPTS",
	},
	"REQUEST_BODY_MISMATCH": {
		Status:  http.StatusBadRequest,
		Message: "Request body validation failed",
		Code:    "REQUEST_BODY_MISMATCH",
	},
	"TTL_INVALID": {
		Status:  http.StatusBadRequest,
		Message: "Invalid TTL value",
		Code:    "TTL_INVALID",
	},
	"RETRY_INVALID": {
		Status:  http.StatusBadRequest,
		Message: "Invalid retry limit",
		Code:    "RETRY_INVALID",
	},
	"CODE_LENGTH_INVALID": {
		Status:  http.StatusBadRequest,
		Message: "Invalid code length",
		Code:    "CODE_LENGTH_INVALID",
	},
	"REDIS_UNAVAILABLE": {
		Status:  http.StatusServiceUnavailable,
		Message: "Redis service is unavailable",
		Code:    "REDIS_UNAVAILABLE",
	},
	"RATE_LIMIT_EXCEEDED": {
		Status:  http.StatusTooManyRequests,
		Message: "Rate limit exceeded",
		Code:    "RATE_LIMIT_EXCEEDED",
	},
}

// RespondWithError sends a JSON error response
func RespondWithError(c *gin.Context, err error) {
	// Convert error to string code
	errCode := err.Error()

	// Check if error exists in predefined responses
	if apiErr, exists := ErrorResponse[errCode]; exists {
		// Don't log validation errors as they're not system errors
		if apiErr.Status >= 500 {
			logger.Error("System error occurred: ", err)
		} else if apiErr.Status >= 400 {
			logger.Warn("Request error: ", err)
		}
		c.JSON(apiErr.Status, apiErr)
		return
	}

	// Log unknown errors
	logger.Error("Unknown error occurred: ", err)
	c.JSON(http.StatusInternalServerError, APIError{
		Status:  http.StatusInternalServerError,
		Message: "Internal server error",
		Code:    "INTERNAL_SERVER_ERROR",
	})
}

// RespondWithSuccess sends a JSON success response
func RespondWithSuccess(c *gin.Context, status int, message string, info interface{}) {
	resp := StandardResponse{
		Status:  status,
		Message: message,
		Info:    info,
	}
	c.JSON(status, resp)
}

func GetCurrentTimestamp() int64 {
	return time.Now().Unix()
}
