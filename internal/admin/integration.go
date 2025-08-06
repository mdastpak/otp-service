package admin

import (
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"otp-service/internal/metrics"
)

// AdminIntegration handles the integration of admin dashboard with the main application
type AdminIntegration struct {
	dashboardManager *DashboardManager
	authManager      *AuthManager
	logger           *logrus.Logger
}

// Config represents admin-specific configuration
type Config struct {
	Enabled     bool     `mapstructure:"enabled"`
	JWTSecret   string   `mapstructure:"jwt_secret"`
	AllowedIPs  []string `mapstructure:"allowed_ips"`
	BasicAuth   bool     `mapstructure:"basic_auth"`
	RequireAuth bool     `mapstructure:"require_auth"`
}

// NewAdminIntegration creates a new admin integration instance
func NewAdminIntegration(metricsService *metrics.Metrics, logger *logrus.Logger, config Config) *AdminIntegration {
	// Use default JWT secret if not provided
	jwtSecret := config.JWTSecret
	if jwtSecret == "" {
		jwtSecret = "your-super-secret-jwt-key-change-in-production"
		logger.Warn("Using default JWT secret - change this in production!")
	}

	dashboardManager := NewDashboardManager(metricsService, logger)
	authManager := NewAuthManager(jwtSecret, logger)

	return &AdminIntegration{
		dashboardManager: dashboardManager,
		authManager:      authManager,
		logger:           logger,
	}
}

// SetupAdminRoutes configures all admin-related routes
func (ai *AdminIntegration) SetupAdminRoutes(router *gin.Engine, config Config) {
	if !config.Enabled {
		ai.logger.Info("Admin dashboard is disabled")
		return
	}

	ai.logger.Info("Setting up admin dashboard routes")

	// Create admin group
	adminGroup := router.Group("/admin")

	// Apply security middlewares
	if len(config.AllowedIPs) > 0 {
		adminGroup.Use(ai.authManager.IPWhitelistMiddleware(config.AllowedIPs))
	}

	// Apply rate limiting
	adminGroup.Use(ai.authManager.RateLimitMiddleware())

	// Authentication routes (no auth required)
	authGroup := adminGroup.Group("/auth")
	ai.authManager.SetupAuthRoutes(authGroup)

	// Login page route (no auth required)
	adminGroup.GET("/login", ai.authManager.ServeLoginPage)

	// Protected routes
	var protectedGroup *gin.RouterGroup

	if config.RequireAuth {
		if config.BasicAuth {
			// Use basic authentication
			protectedGroup = adminGroup.Group("/", ai.authManager.BasicAuthMiddleware())
		} else {
			// Use JWT authentication
			protectedGroup = adminGroup.Group("/", ai.authManager.JWTAuthMiddleware())
		}
	} else {
		// No authentication required (development only)
		ai.logger.Warn("Admin dashboard running without authentication - NOT recommended for production!")
		protectedGroup = adminGroup.Group("/")
	}

	// Setup dashboard routes
	ai.dashboardManager.SetupRoutes(protectedGroup)

	ai.logger.Info("Admin dashboard available at /admin/")
}

// GetDashboardManager returns the dashboard manager for external access
func (ai *AdminIntegration) GetDashboardManager() *DashboardManager {
	return ai.dashboardManager
}

// GetAuthManager returns the auth manager for external access
func (ai *AdminIntegration) GetAuthManager() *AuthManager {
	return ai.authManager
}

// AddActivity adds an activity to the dashboard (convenience method)
func (ai *AdminIntegration) AddActivity(activityType, message string) {
	ai.dashboardManager.AddActivity(activityType, message)
}