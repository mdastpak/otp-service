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
	ServerMode  string   // Pass server mode for test mode bypassing
}

// NewAdminIntegration creates a new admin integration instance
func NewAdminIntegration(metricsService *metrics.Metrics, logger *logrus.Logger, config Config) *AdminIntegration {
	return newAdminIntegration(metricsService, logger, config, "")
}

// NewAdminIntegrationWithMode creates a new admin integration instance with server mode
func NewAdminIntegrationWithMode(metricsService *metrics.Metrics, logger *logrus.Logger, config Config, serverMode string) *AdminIntegration {
	return newAdminIntegration(metricsService, logger, config, serverMode)
}

func newAdminIntegration(metricsService *metrics.Metrics, logger *logrus.Logger, config Config, serverMode string) *AdminIntegration {
	// Use default JWT secret if not provided
	jwtSecret := config.JWTSecret
	if jwtSecret == "" {
		jwtSecret = "your-super-secret-jwt-key-change-in-production"
		logger.Warn("Using default JWT secret - change this in production!")
	}

	dashboardManager := NewDashboardManager(metricsService, logger)
	var authManager *AuthManager
	if serverMode != "" {
		authManager = NewAuthManagerWithMode(jwtSecret, logger, serverMode)
	} else {
		authManager = NewAuthManager(jwtSecret, logger)
	}

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

	// Main /admin route with access control
	router.GET("/admin", ai.authManager.AdminAccessMiddleware(config.AllowedIPs, config.ServerMode))
	router.GET("/admin/", ai.authManager.AdminAccessMiddleware(config.AllowedIPs, config.ServerMode))

	// Create admin group for other routes
	adminGroup := router.Group("/admin")

	// Apply rate limiting
	adminGroup.Use(ai.authManager.RateLimitMiddleware())

	// Authentication routes (no additional auth required)
	authGroup := adminGroup.Group("/auth")
	// Apply IP whitelist to auth routes
	if len(config.AllowedIPs) > 0 {
		authGroup.Use(ai.authManager.IPWhitelistMiddleware(config.AllowedIPs, config.ServerMode))
	}
	ai.authManager.SetupAuthRoutes(authGroup)

	// Login page route (with IP whitelist only)
	loginGroup := adminGroup.Group("/login")
	if len(config.AllowedIPs) > 0 {
		loginGroup.Use(ai.authManager.IPWhitelistMiddleware(config.AllowedIPs, config.ServerMode))
	}
	loginGroup.GET("", ai.authManager.ServeLoginPage)
	loginGroup.GET("/", ai.authManager.ServeLoginPage)

	// Dashboard HTML page (IP whitelist only - auth checked client-side)
	dashboardHTMLGroup := adminGroup.Group("/dashboard")
	if len(config.AllowedIPs) > 0 {
		dashboardHTMLGroup.Use(ai.authManager.IPWhitelistMiddleware(config.AllowedIPs, config.ServerMode))
	}
	// Serve static files for dashboard (no auth required)
	dashboardHTMLGroup.Static("/static", "./web/admin/static")
	// Serve dashboard HTML without JWT requirement
	dashboardHTMLGroup.GET("", ai.dashboardManager.ServeDashboardHTML)
	dashboardHTMLGroup.GET("/", ai.dashboardManager.ServeDashboardHTML)
	
	// Protected API routes (require JWT)
	protectedGroup := adminGroup.Group("/")
	// Apply IP whitelist first
	if len(config.AllowedIPs) > 0 {
		protectedGroup.Use(ai.authManager.IPWhitelistMiddleware(config.AllowedIPs, config.ServerMode))
	}
	
	if config.RequireAuth {
		if config.BasicAuth {
			// Use basic authentication
			protectedGroup.Use(ai.authManager.BasicAuthMiddleware())
		} else {
			// Use JWT authentication
			protectedGroup.Use(ai.authManager.JWTAuthMiddleware(config.ServerMode))
		}
	} else {
		// No authentication required (development only)
		ai.logger.Warn("Admin dashboard running without authentication - NOT recommended for production!")
	}

	// Setup protected API routes
	ai.dashboardManager.SetupProtectedRoutes(protectedGroup)

	ai.logger.Info("Admin dashboard available at /admin/ (redirects to /admin/dashboard)")
	ai.logger.Info("Admin login available at /admin/login")
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