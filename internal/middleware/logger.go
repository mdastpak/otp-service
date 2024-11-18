// internal/middleware/logger.go

package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
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

		// Calculate latency
		latency := time.Since(start)

		// Get client IP
		clientIP := c.ClientIP()

		// Get response status
		status := c.Writer.Status()

		if raw != "" {
			path = path + "?" + raw
		}

		// Log the details
		logrus.WithFields(logrus.Fields{
			"status":    status,
			"latency":   latency,
			"client_ip": clientIP,
			"method":    c.Request.Method,
			"path":      path,
			"errors":    c.Errors.String(),
		}).Info("Request processed")
	}
}
