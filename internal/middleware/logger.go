// internal/middleware/logger.go

package middleware

import (
	"otp-service/pkg/logger"
	"time"

	"github.com/gin-gonic/gin"
)

func (m *Middleware) Logger() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Start timer
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Process request
		c.Next()

		// Skip logging for health checks
		if path == "/health" {
			return
		}

		// Get response status and latency
		latency := time.Since(start)
		status := c.Writer.Status()

		if raw != "" {
			path = path + "?" + raw
		}

		// Collect errors if any
		var errorMessages string
		for _, err := range c.Errors {
			errorMessages += err.Error() + ";"
		}

		// Determine log level based on status code
		logFields := map[string]interface{}{
			"status":    status,
			"latency":   latency,
			"client_ip": c.ClientIP(),
			"method":    c.Request.Method,
			"path":      path,
		}

		if errorMessages != "" {
			logFields["errors"] = errorMessages
		}

		if status >= 500 {
			logger.Error("Request failed", logFields)
		} else if status >= 400 {
			logger.Warn("Request warning", logFields)
		} else {
			logger.Info("Request processed", logFields)
		}
	}
}
