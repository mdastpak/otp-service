// internal/handler/health.go

package handler

import (
	"net/http"
	"otp-service/pkg/utils"

	"github.com/gin-gonic/gin"
)

type HealthHandler struct {
	BaseHandler
}

func NewHealthHandler() *HealthHandler {
	return &HealthHandler{}
}

// Check handles health check requests
func (h *HealthHandler) Check(c *gin.Context) {
	utils.RespondWithSuccess(c, http.StatusOK, "SERVICE_HEALTH", gin.H{
		"status":       "UP",
		"redis_status": "OK",
		"version":      "1.0.0",
		"timestamp":    utils.GetCurrentTimestamp(),
	})
}
