// internal/handler/otp.go

package handler

import (
	"net/http"
	"otp-service/internal/domain"
	"otp-service/pkg/utils"

	"github.com/gin-gonic/gin"
)

type OTPHandler struct {
	service domain.OTPService
}

func NewOTPHandler(service domain.OTPService) *OTPHandler {
	return &OTPHandler{
		service: service,
	}
}

// GenerateOTP handles OTP generation requests
func (h *OTPHandler) GenerateOTP(c *gin.Context) {
	var req domain.OTPRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		utils.RespondWithError(c, domain.ErrInvalidRequest)
		return
	}

	resp, err := h.service.Generate(c.Request.Context(), &req)
	if err != nil {
		utils.RespondWithError(c, err)
		return
	}

	utils.RespondWithSuccess(c, http.StatusOK, "OTP_GENERATED", resp.Info)
}

// VerifyOTP handles OTP verification requests
func (h *OTPHandler) VerifyOTP(c *gin.Context) {
	uuid := c.Query("uuid")
	code := c.Query("otp")

	if uuid == "" || code == "" {
		utils.RespondWithError(c, domain.ErrMissingParameters)
		return
	}

	if err := h.service.Verify(c.Request.Context(), uuid, code); err != nil {
		utils.RespondWithError(c, err)
		return
	}

	utils.RespondWithSuccess(c, http.StatusOK, "OTP_VERIFIED", nil)
}

// HealthCheck handles health check requests
func (h *OTPHandler) HealthCheck(c *gin.Context) {
	utils.RespondWithSuccess(c, http.StatusOK, "SERVICE_HEALTH", gin.H{
		"redis_status": "OK",
	})
}
