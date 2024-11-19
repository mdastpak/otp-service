// internal/middleware/logger.go

package middleware

import (
	"otp-service/pkg/logger"
	"time"

	"github.com/gin-gonic/gin"
)

func (m *Middleware) Logger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Process request
		c.Next()

		// Skip logging for health checks
		if path == "/health" {
			return
		}

		// Calculate latency
		latency := time.Since(start)
		status := c.Writer.Status()

		if raw != "" {
			path = path + "?" + raw
		}

		logFields := map[string]interface{}{
			"status":    status,
			"latency":   latency,
			"client_ip": c.ClientIP(),
			"method":    c.Request.Method,
			"path":      path,
		}

		// Only log errors from context if status is error
		if status >= 400 {
			if len(c.Errors) > 0 {
				logFields["errors"] = c.Errors.String()
			}
		}

		// Log based on status code
		if status >= 500 {
			logger.Error("Request failed", logFields)
		} else if status >= 400 {
			logger.Warn("Request warning", logFields)
		} else {
			logger.Info("Request processed", logFields)
		}
	}
}
