// cmd/server/main.go

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	redisClient "github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"

	"otp-service/config"
	"otp-service/internal/handler"
	"otp-service/internal/middleware"
	"otp-service/internal/repository/redis"
	"otp-service/internal/service"
	"otp-service/pkg/logger"
)

var (
	log *logrus.Logger
	rdb *redisClient.Client
)

func main() {
	// Initialize logger
	logger.InitLogger(&logger.Config{
		Level:        "debug",
		ReportCaller: true,
		JSONFormat:   true,
	})
	log = logger.GetLogger()
	log.Info("Starting OTP service...")

	// Load configuration
	cfg, err := config.LoadConfig("config/config.yaml")
	if err != nil {
		log.Fatal("Failed to load config: ", err)
	}

	// Set Gin mode
	gin.SetMode(cfg.Server.Mode)

	// Initialize Redis connection
	rdb = initRedisClient(cfg)
	defer rdb.Close()

	// Initialize dependencies
	otpRepo := redis.NewOTPRepository(rdb, cfg.Redis.KeyPrefix)
	otpService := service.NewOTPService(otpRepo)
	otpHandler := handler.NewOTPHandler(otpService)
	healthHandler := handler.NewHealthHandler()

	// Initialize router
	router := gin.New()

	// Initialize middleware
	m := middleware.NewMiddleware(cfg)

	// Apply middleware
	router.Use(m.Logger())
	router.Use(m.Security())
	router.Use(m.CORS())
	router.Use(m.RateLimit())
	router.Use(m.Metrics())
	router.Use(checkRedisConnection())

	// Start cleanup goroutine for rate limiter
	m.CleanupLimiters()

	// Register routes
	router.POST("/", otpHandler.GenerateOTP)
	router.GET("/", otpHandler.VerifyOTP)
	router.GET("/health", healthHandler.Check)

	// Create server
	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%s", cfg.Server.Host, cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  time.Duration(cfg.Server.Timeout.Read) * time.Second,
		WriteTimeout: time.Duration(cfg.Server.Timeout.Write) * time.Second,
		IdleTimeout:  time.Duration(cfg.Server.Timeout.Idle) * time.Second,
	}

	// Start server in a goroutine
	go func() {
		log.Info("Server starting on ", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start server: ", err)
		}
	}()

	// Start Redis health check goroutine
	go monitorRedisConnection(cfg)

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down server...")

	// Shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown: ", err)
	}

	log.Info("Server exited successfully")
}

func initRedisClient(cfg *config.Config) *redisClient.Client {
	rdb := redisClient.NewClient(&redisClient.Options{
		Addr:        fmt.Sprintf("%s:%s", cfg.Redis.Host, cfg.Redis.Port),
		Password:    cfg.Redis.Password,
		DB:          cfg.Redis.DB,
		DialTimeout: time.Duration(cfg.Redis.Timeout) * time.Second,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Error("Failed to connect to Redis: ", err)
		return rdb // Return client anyway to allow service to start
	}

	log.Info("Successfully connected to Redis")
	return rdb
}

func checkRedisConnection() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.Path == "/health" {
			c.Next()
			return
		}

		ctx := c.Request.Context()
		if err := rdb.Ping(ctx).Err(); err != nil {
			log.Error("Redis connection failed: ", err)
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
				"status":  http.StatusServiceUnavailable,
				"message": "REDIS_UNAVAILABLE",
			})
			return
		}
		c.Next()
	}
}

func monitorRedisConnection(cfg *config.Config) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		ctx := context.Background()
		if err := rdb.Ping(ctx).Err(); err != nil {
			log.Error("Redis health check failed: ", err)
			// Try to reconnect
			rdb = initRedisClient(cfg)
		}
	}
}
