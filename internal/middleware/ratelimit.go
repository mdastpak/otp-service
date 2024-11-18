// internal/middleware/ratelimit.go

package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

const (
	defaultRateLimit = 10 // requests per second
	defaultBurst     = 20
)

func (m *Middleware) RateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		limiter := m.getLimiter(clientIP)

		if !limiter.Allow() {
			c.AbortWithStatusJSON(429, gin.H{
				"status":  429,
				"message": "RATE_LIMIT_EXCEEDED",
				"info": gin.H{
					"retry_after": "1s",
				},
			})
			return
		}

		c.Next()
	}
}

func (m *Middleware) getLimiter(clientIP string) *rate.Limiter {
	m.mu.Lock()
	defer m.mu.Unlock()

	limiter, exists := m.clients[clientIP]
	if !exists {
		limiter = rate.NewLimiter(rate.Every(time.Second/defaultRateLimit), defaultBurst)
		m.clients[clientIP] = limiter
	}

	return limiter
}

// CleanupLimiters periodically removes old limiters
func (m *Middleware) CleanupLimiters() {
	go func() {
		for {
			time.Sleep(time.Hour)
			m.mu.Lock()
			m.clients = make(map[string]*rate.Limiter)
			m.mu.Unlock()
		}
	}()
}
