// internal/handler/health.go

package handler

import (
	"net/http"
	"otp-service/config"
	"otp-service/pkg/utils"

	"github.com/gin-gonic/gin"
)

type HealthHandler struct {
	BaseHandler
	config *config.Config
}

func NewHealthHandler(cfg *config.Config) *HealthHandler {
	return &HealthHandler{
		config: cfg,
	}
}

func (h *HealthHandler) Check(c *gin.Context) {
	// Basic health info
	healthInfo := gin.H{
		"status":       "UP",
		"redis_status": "OK",
		"version":      "1.0.0",
		"timestamp":    utils.GetCurrentTimestamp(),
		"mode":         h.config.Server.Mode,
	}

	// Add config information in debug/test mode
	if h.config.Server.Mode == "debug" || h.config.Server.Mode == "test" {
		healthInfo["config"] = gin.H{
			"redis": gin.H{
				"host":       h.config.Redis.Host,
				"port":       h.config.Redis.Port,
				"db":         h.config.Redis.DB,
				"key_prefix": h.config.Redis.KeyPrefix,
				"timeout":    h.config.Redis.Timeout,
				"hash_keys":  h.config.Redis.HashKeys,
			},
			"server": gin.H{
				"host": h.config.Server.Host,
				"port": h.config.Server.Port,
				"timeout": gin.H{
					"read":        h.config.Server.Timeout.Read,
					"write":       h.config.Server.Timeout.Write,
					"idle":        h.config.Server.Timeout.Idle,
					"read_header": h.config.Server.Timeout.ReadHeader,
				},
				"tls": gin.H{
					"enabled":      h.config.Server.TLS.Enabled,
					"cert_file":    h.config.Server.TLS.CertFile,
					"key_file":     h.config.Server.TLS.KeyFile,
					"client_certs": h.config.Server.TLS.ClientCerts,
				},
			},
		}
	}

	utils.RespondWithSuccess(c, http.StatusOK, "SERVICE_HEALTH", healthInfo)
}
