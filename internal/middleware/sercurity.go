// internal/middleware/security.go

package middleware

import (
	"github.com/gin-gonic/gin"
)

func (m *Middleware) Security() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Security headers
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Content-Security-Policy", "default-src 'self'")

		// HSTS if TLS is enabled
		if m.config.Server.TLS.Enabled {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		// Prevent MIME-sniffing
		c.Header("X-Content-Type-Options", "nosniff")

		// Referrer Policy
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

		// Permissions Policy
		c.Header("Permissions-Policy", "geolocation=(), midi=(), notifications=(), push=(), sync-xhr=(), microphone=(), camera=(), magnetometer=(), gyroscope=(), speaker=()")

		c.Next()
	}
}

// TLSMiddleware enforces HTTPS
func (m *Middleware) TLSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if m.config.Server.TLS.Enabled {
			if c.Request.Header.Get("X-Forwarded-Proto") != "https" {
				c.AbortWithStatusJSON(400, gin.H{
					"status":  400,
					"message": "HTTPS_REQUIRED",
				})
				return
			}
		}
		c.Next()
	}
}
