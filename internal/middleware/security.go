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
		// Only add security headers if enabled
		if !cfg.Security.HeadersEnabled {
			c.Next()
			return
		}

		// Clickjacking Protection
		c.Header("X-Frame-Options", "DENY")

		// Prevent MIME type sniffing
		c.Header("X-Content-Type-Options", "nosniff")

		// XSS Protection in browsers
		c.Header("X-XSS-Protection", "1; mode=block")

		c.Header("X-Permitted-Cross-Domain-Policies", "none")

		// Content Security Policy Configuration
		if cfg.Security.CSPPolicy != "" {
			c.Header("Content-Security-Policy", cfg.Security.CSPPolicy)
		} else {
			// Default CSP policy
			csp := []string{
				"default-src 'self'",
				"script-src 'self' 'unsafe-inline' 'unsafe-eval'",
				"style-src 'self' 'unsafe-inline'",
				"img-src 'self' data:",
				"font-src 'self'",
				"form-action 'self'",
				"frame-ancestors 'none'",
				"base-uri 'self'",
				"block-all-mixed-content",
			}
			c.Header("Content-Security-Policy", strings.Join(csp, "; "))
		}

		// Add Referrer Policy
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

		// HSTS Configuration - Use configured max age
		if cfg.Server.TLS.Enabled && cfg.Security.HSTSMaxAge != "0" {
			c.Header("Strict-Transport-Security", "max-age="+cfg.Security.HSTSMaxAge+"; includeSubDomains; preload")
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

// CORS adds CORS headers to prevent CSRF attacks
func CORS(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		
		// Parse allowed origins from configuration
		allowedOrigins := strings.Split(cfg.CORS.AllowedOrigins, ",")
		for i, o := range allowedOrigins {
			allowedOrigins[i] = strings.TrimSpace(o)
		}
		
		// Check if origin is allowed and set appropriate header
		if cfg.CORS.AllowedOrigins == "*" {
			// Allow all origins
			c.Header("Access-Control-Allow-Origin", "*")
		} else {
			// Check specific origins
			for _, allowedOrigin := range allowedOrigins {
				if origin == allowedOrigin {
					c.Header("Access-Control-Allow-Origin", origin)
					break
				}
			}
		}
		
		// Set CORS headers using configuration
		c.Header("Access-Control-Allow-Methods", cfg.CORS.AllowedMethods)
		c.Header("Access-Control-Allow-Headers", cfg.CORS.AllowedHeaders)
		
		// Set exposed headers if configured
		if cfg.CORS.ExposedHeaders != "" {
			c.Header("Access-Control-Expose-Headers", cfg.CORS.ExposedHeaders)
		}
		
		// Set credentials policy
		c.Header("Access-Control-Allow-Credentials", cfg.CORS.AllowCredentials)
		
		// Set max age for preflight
		c.Header("Access-Control-Max-Age", cfg.CORS.MaxAge)
		
		// Handle preflight requests
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		
		c.Next()
	}
}

// RequestSizeLimit limits request body size to prevent resource exhaustion
func RequestSizeLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Limit request body size to 1MB to prevent resource exhaustion
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1024*1024)
		c.Next()
	}
}
