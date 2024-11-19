// cmd/server/main.go

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	redisClient "github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"

	"otp-service/config"
	"otp-service/internal/handler"
	"otp-service/internal/middleware"
	"otp-service/internal/repository/redis"
	"otp-service/internal/service"
	"otp-service/pkg/logger"
	"otp-service/pkg/utils"
)

type redisManager struct {
	client *redisClient.Client
	mu     sync.RWMutex
}

var (
	log      *logrus.Logger
	rdb      *redisClient.Client
	redisMgr = &redisManager{
		mu: sync.RWMutex{},
	}
)

func main() {
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatal("Failed to load config: ", err)
	}

	// Initialize logger based on mode
	logger.InitLogger(&logger.Config{
		Mode: cfg.Server.Mode,
	})
	log = logger.GetLogger()

	// Set Gin mode based on configuration
	switch cfg.Server.Mode {
	case "debug":
		gin.SetMode(gin.DebugMode)
		log.Debug("Running in DEBUG mode")
	case "test":
		gin.SetMode(gin.TestMode)
		log.Debug("Running in TEST mode")
	case "release":
		gin.SetMode(gin.ReleaseMode)
		log.Info("Running in RELEASE mode")
	default:
		gin.SetMode(gin.ReleaseMode)
		log.Warn("Unknown mode, defaulting to RELEASE mode")
	}

	// Initialize Redis connection
	rdb, keyMgr := initRedisClient(cfg)
	if rdb == nil {
		log.Warn("Initial Redis connection failed, will retry in background")
	} else {
		redisMgr.setClient(rdb)
		log.Info("Initial Redis connection successful")
	}
	defer rdb.Close()

	// Start Redis connection monitoring
	go monitorRedisConnection(cfg)

	// Initialize dependencies
	otpRepo := redis.NewOTPRepository(rdb, keyMgr)

	otpService := service.NewOTPService(otpRepo, cfg.Server.Mode)
	otpHandler := handler.NewOTPHandler(otpService)
	healthHandler := handler.NewHealthHandler(cfg)

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

	if cfg.Server.Mode == "debug" || cfg.Server.Mode == "test" {
		middleware.MonitorRedisDistribution(otpRepo)
	}

	// Start cleanup goroutine for rate limiter

	m.CleanupLimiters()

	// Register routes
	router.POST("/", otpHandler.GenerateOTP)
	router.GET("/", otpHandler.VerifyOTP)
	router.GET("/health", healthHandler.Check)
	router.GET("/metrics", gin.WrapH(promhttp.Handler()))

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

func (rm *redisManager) setClient(client *redisClient.Client) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	if rm.client != nil {
		_ = rm.client.Close()
	}
	rm.client = client
}

func (rm *redisManager) getClient() *redisClient.Client {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.client
}

func initRedisClient(cfg *config.Config) (*redisClient.Client, *utils.RedisKeyManager) {
	keyMgr := utils.NewRedisKeyManager(utils.RedisKeyConfig{
		KeyPrefix: cfg.Redis.KeyPrefix,
		HashKeys:  cfg.Redis.HashKeys,
		DB:        cfg.Redis.DB,
	})

	// Test distribution in debug mode
	if cfg.Server.Mode == "debug" {
		testUUIDs := make([]string, 100)
		for i := 0; i < 100; i++ {
			testUUIDs[i] = uuid.New().String()
		}
		distribution := keyMgr.DebugShardDistribution(testUUIDs)
		log.Debug("Redis shard distribution simulation: ", distribution)
	}

	selectedDB, err := keyMgr.GetShardIndex("initial")
	if err != nil {
		log.Error("Failed to determine Redis DB: ", err)
		selectedDB = 0
	}

	client := redisClient.NewClient(&redisClient.Options{
		Addr:        fmt.Sprintf("%s:%s", cfg.Redis.Host, cfg.Redis.Port),
		Password:    cfg.Redis.Password,
		DB:          selectedDB,
		DialTimeout: time.Duration(cfg.Redis.Timeout) * time.Second,
	})

	return client, keyMgr
}

func checkRedisConnection() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip health check endpoint
		if c.Request.URL.Path == "/health" {
			c.Next()
			return
		}

		client := redisMgr.getClient()
		if client == nil {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
				"status":  http.StatusServiceUnavailable,
				"message": "REDIS_UNAVAILABLE",
			})
			return
		}

		err := client.Ping(c.Request.Context()).Err()
		if err != nil {
			log.Error("Redis connection check failed: ", err)
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
		client := redisMgr.getClient()
		if client == nil {
			log.Warn("Redis client is nil, attempting to initialize")
			newClient, _ := initRedisClient(cfg)
			if newClient != nil {
				redisMgr.setClient(newClient)
				log.Info("Successfully initialized Redis connection")
			}
			continue
		}

		ctx := context.Background()
		if err := client.Ping(ctx).Err(); err != nil {
			log.Error("Redis health check failed: ", err)

			// Try to reconnect
			newClient, _ := initRedisClient(cfg)

			if err := newClient.Ping(ctx).Err(); err != nil {
				log.Error("Redis reconnection failed: ", err)
				newClient.Close()
				continue
			}

			// If reconnection was successful, update the client
			redisMgr.setClient(newClient)
			log.Info("Successfully reconnected to Redis")
		}
	}
}
