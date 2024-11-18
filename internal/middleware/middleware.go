// internal/middleware/middleware.go

package middleware

import (
	"otp-service/config"
	"sync"

	"golang.org/x/time/rate"
)

type Middleware struct {
	config  *config.Config
	clients map[string]*rate.Limiter
	mu      sync.RWMutex
}

func NewMiddleware(cfg *config.Config) *Middleware {
	return &Middleware{
		config:  cfg,
		clients: make(map[string]*rate.Limiter),
	}
}
