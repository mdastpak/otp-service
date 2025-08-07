package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"otp-service/internal/config"
	"otp-service/internal/models"
	"otp-service/internal/redis"
)

// SecurityHeaders adds security headers to the response
func SecurityHeaders(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Clickjacking Protection
		c.Header("X-Frame-Options", "DENY")

		// Prevent MIME type sniffing
		c.Header("X-Content-Type-Options", "nosniff")

		// XSS Protection in browsers
		c.Header("X-XSS-Protection", "1; mode=block")

		c.Header("X-Permitted-Cross-Domain-Policies", "none")

		// Content Security Policy Configuration
		csp := []string{
			"default-src 'self'",
			"script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net",
			"style-src 'self' 'unsafe-inline'",
			"img-src 'self' data:",
			"font-src 'self'",
			"connect-src 'self' ws: wss:",
			"form-action 'self'",
			"frame-ancestors 'none'",
			"base-uri 'self'",
			"block-all-mixed-content",
		}
		c.Header("Content-Security-Policy", strings.Join(csp, "; "))

		// Add Referrer Policy
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

		// HSTS Configuration - Only in production environment with SSL
		if cfg.Server.TLS.Enabled {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}
		c.Header("X-Download-Options", "noopen")
		c.Header("X-DNS-Prefetch-Control", "off")

		// Prevent caching sensitive data
		c.Header("Cache-Control", "no-store, max-age=0")
		c.Header("Pragma", "no-cache")

		// Limit information leakage about the server
		c.Header("X-Powered-By", "")
		c.Header("Server", "")

		// Add Permissions-Policy header
		featurePolicy := []string{
			"camera 'none'",
			"microphone 'none'",
			"geolocation 'none'",
			"payment 'none'",
			"usb 'none'",
			"fullscreen 'self'",
		}
		c.Header("Permissions-Policy", strings.Join(featurePolicy, ", "))

		// Cross-Origin policies
		c.Header("Cross-Origin-Embedder-Policy", "require-corp")
		c.Header("Cross-Origin-Opener-Policy", "same-origin")
		c.Header("Cross-Origin-Resource-Policy", "same-origin")

		c.Next()
	}
}

// HealthCheck is a middleware that checks the health of Redis before processing each request
func HealthCheck(redisClient redis.RedisInterface) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := redisClient.Ping(); err != nil {
			responseData := map[string]interface{}{
				"redis_status": "Unavailable",
				"config":       "***********",
			}

			c.JSON(http.StatusServiceUnavailable, models.APIResponse{
				Status:  http.StatusServiceUnavailable,
				Message: models.StatusServiceHealth,
				Info:    responseData,
			})
			c.Abort()
			return
		}
		c.Next()
	}
}
