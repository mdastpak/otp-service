// internal/handler/otp.go

package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"otp-service/internal/domain"
	"otp-service/pkg/logger"
	"otp-service/pkg/utils"

	"github.com/gin-gonic/gin"
)

type OTPHandler struct {
	BaseHandler
	service domain.OTPService
}

func NewOTPHandler(service domain.OTPService) *OTPHandler {
	return &OTPHandler{
		service: service,
	}
}

func (h *OTPHandler) GenerateOTP(c *gin.Context) {
	var req domain.OTPRequest

	// Set default values
	req = domain.OTPRequest{
		TTL:              60,
		RetryLimit:       5,
		CodeLength:       6,
		StrictValidation: false,
		UseAlphaNumeric:  false,
	}

	// First bind query parameters
	if err := c.ShouldBindQuery(&req); err != nil {
		utils.RespondWithError(c, fmt.Errorf("%w: %v", domain.ErrInvalidRequest, err))
		return
	}

	// If strict validation is enabled, read and store raw JSON body
	if req.StrictValidation {
		if c.Request.Body == nil {
			utils.RespondWithError(c, domain.ErrRequestBodyMismatch)
			return
		}

		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			utils.RespondWithError(c, fmt.Errorf("failed to read request body: %w", err))
			return
		}

		// Verify if body is valid JSON
		if !json.Valid(body) {
			utils.RespondWithError(c, domain.ErrRequestBodyMismatch)
			return
		}

		req.RawJSON = json.RawMessage(body)

		// Log for debugging
		logger.Debug(fmt.Sprintf("Received JSON body for strict validation: %s", string(body)))
	}

	resp, err := h.service.Generate(c.Request.Context(), &req)
	if err != nil {
		utils.RespondWithError(c, err)
		return
	}

	utils.RespondWithSuccess(c, http.StatusOK, "OTP_GENERATED", resp.Info)
}

func (h *OTPHandler) VerifyOTP(c *gin.Context) {
	// First get UUID and code from query params
	uuid := c.Query("uuid")
	code := c.Query("otp")

	if uuid == "" || code == "" {
		utils.RespondWithError(c, domain.ErrMissingParameters)
		return
	}

	var req domain.VerifyRequest
	req.UUID = uuid
	req.Code = code

	// If content type is JSON, bind the body
	if c.GetHeader("Content-Type") == "application/json" {
		if err := c.ShouldBindJSON(&req.StrictRequest); err != nil {
			logger.Debug("Failed to bind JSON body: ", err)
			utils.RespondWithError(c, domain.ErrRequestBodyMismatch)
			return
		}
		logger.Debug(fmt.Sprintf("Received verification request with JSON body: %s", string(req.StrictRequest)))
	}

	if err := h.service.Verify(c.Request.Context(), &req); err != nil {
		utils.RespondWithError(c, err)
		return
	}

	utils.RespondWithSuccess(c, http.StatusOK, "OTP_VERIFIED", nil)
}
