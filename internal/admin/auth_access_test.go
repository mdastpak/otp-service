package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuthAccessSuite contains all admin access control tests
type TestAuthAccessSuite struct {
	authManager    *AuthManager
	router         *gin.Engine
	logger         *logrus.Logger
	jwtSecret      string
	allowedIPs     []string
	testToken      string
	expiredToken   string
	invalidToken   string
}

func setupTestAuthSuite(t *testing.T, serverMode string) *TestAuthAccessSuite {
	// Setup logger with test level
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Reduce noise in tests

	// Test configuration
	jwtSecret := "test-jwt-secret-key-for-testing"
	allowedIPs := []string{"192.168.1.100", "10.0.0.50"}

	// Create auth manager
	var authManager *AuthManager
	if serverMode == "test" {
		authManager = NewAuthManagerWithMode(jwtSecret, logger, serverMode)
	} else {
		authManager = NewAuthManager(jwtSecret, logger)
	}

	// Setup router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Setup routes similar to production
	router.GET("/admin", authManager.AdminAccessMiddleware(allowedIPs, serverMode))
	router.GET("/admin/", authManager.AdminAccessMiddleware(allowedIPs, serverMode))
	
	adminGroup := router.Group("/admin")
	adminGroup.Use(authManager.RateLimitMiddleware())
	
	// Auth routes
	authGroup := adminGroup.Group("/auth")
	if serverMode != "test" {
		authGroup.Use(authManager.IPWhitelistMiddleware(allowedIPs, serverMode))
	}
	authManager.SetupAuthRoutes(authGroup)
	
	// Login routes
	loginGroup := adminGroup.Group("/login")
	if serverMode != "test" {
		loginGroup.Use(authManager.IPWhitelistMiddleware(allowedIPs, serverMode))
	}
	loginGroup.GET("", authManager.ServeLoginPage)
	
	// Dashboard routes
	dashboardGroup := adminGroup.Group("/dashboard")
	if serverMode != "test" {
		dashboardGroup.Use(authManager.IPWhitelistMiddleware(allowedIPs, serverMode))
	}
	dashboardGroup.Use(authManager.JWTAuthMiddleware(serverMode))
	dashboardGroup.GET("", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "dashboard"})
	})
	dashboardGroup.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "dashboard"})
	})

	suite := &TestAuthAccessSuite{
		authManager: authManager,
		router:      router,
		logger:      logger,
		jwtSecret:   jwtSecret,
		allowedIPs:  allowedIPs,
	}

	// Generate test tokens
	suite.generateTestTokens(t)

	return suite
}

func (suite *TestAuthAccessSuite) generateTestTokens(t *testing.T) {
	// Valid token
	claims := &AdminClaims{
		Username: "admin",
		Role:     "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "otp-service-admin",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	validToken, err := token.SignedString([]byte(suite.jwtSecret))
	require.NoError(t, err)
	suite.testToken = validToken

	// Expired token
	expiredClaims := &AdminClaims{
		Username: "admin",
		Role:     "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-25 * time.Hour)),
			Issuer:    "otp-service-admin",
		},
	}
	expiredTokenObj := jwt.NewWithClaims(jwt.SigningMethodHS256, expiredClaims)
	expiredToken, err := expiredTokenObj.SignedString([]byte(suite.jwtSecret))
	require.NoError(t, err)
	suite.expiredToken = expiredToken

	// Invalid token
	suite.invalidToken = "invalid.jwt.token"
}

// Production Mode Tests
func TestProductionModeAdminAccess(t *testing.T) {
	suite := setupTestAuthSuite(t, "production")

	t.Run("ProductionMode_IPWhitelist_Tests", func(t *testing.T) {
		suite.testProductionIPWhitelist(t)
	})

	t.Run("ProductionMode_JWT_Tests", func(t *testing.T) {
		suite.testProductionJWTValidation(t)
	})

	t.Run("ProductionMode_Login_Tests", func(t *testing.T) {
		suite.testProductionLogin(t)
	})

	t.Run("ProductionMode_Redirect_Tests", func(t *testing.T) {
		suite.testProductionRedirects(t)
	})
}

// Test Mode Tests
func TestTestModeAdminAccess(t *testing.T) {
	suite := setupTestAuthSuite(t, "test")

	t.Run("TestMode_Bypass_Tests", func(t *testing.T) {
		suite.testModeBypass(t)
	})

	t.Run("TestMode_Credentials_Tests", func(t *testing.T) {
		suite.testModeCredentials(t)
	})
}

func (suite *TestAuthAccessSuite) testProductionIPWhitelist(t *testing.T) {
	tests := []struct {
		name           string
		clientIP       string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Allowed IP should show login page",
			clientIP:       "192.168.1.100",
			expectedStatus: 200,
			expectedBody:   "Admin Login",
		},
		{
			name:           "Localhost should show login page",
			clientIP:       "127.0.0.1",
			expectedStatus: 200,
			expectedBody:   "Admin Login",
		},
		{
			name:           "IPv6 localhost should show login page", 
			clientIP:       "::1",
			expectedStatus: 200,
			expectedBody:   "Admin Login",
		},
		{
			name:           "Non-whitelisted IP should show restriction page",
			clientIP:       "203.0.113.1",
			expectedStatus: 403,
			expectedBody:   "Access Restricted",
		},
		{
			name:           "Private IP not in whitelist should be restricted",
			clientIP:       "192.168.1.101",
			expectedStatus: 403,
			expectedBody:   "Access Restricted",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/admin", nil)
			req.Header.Set("X-Forwarded-For", tt.clientIP)
			if tt.clientIP == "::1" {
				req.RemoteAddr = "[::1]:12345"
			} else {
				req.RemoteAddr = tt.clientIP + ":12345"
			}
			
			w := httptest.NewRecorder()
			suite.router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.Contains(t, w.Body.String(), tt.expectedBody)

			if tt.expectedStatus == 403 {
				// Check that client IP is shown in restriction page
				assert.Contains(t, w.Body.String(), tt.clientIP)
			}
		})
	}
}

func (suite *TestAuthAccessSuite) testProductionJWTValidation(t *testing.T) {
	allowedIP := "192.168.1.100"
	
	tests := []struct {
		name           string
		token          string
		expectedStatus int
		expectRedirect bool
		redirectURL    string
	}{
		{
			name:           "Valid JWT should redirect to dashboard",
			token:          suite.testToken,
			expectedStatus: 302,
			expectRedirect: true,
			redirectURL:    "/admin/dashboard",
		},
		{
			name:           "Expired JWT should show login page",
			token:          suite.expiredToken,
			expectedStatus: 200,
			expectRedirect: false,
		},
		{
			name:           "Invalid JWT should show login page",
			token:          suite.invalidToken,
			expectedStatus: 200,
			expectRedirect: false,
		},
		{
			name:           "No JWT should show login page",
			token:          "",
			expectedStatus: 200,
			expectRedirect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/admin", nil)
			req.Header.Set("X-Forwarded-For", allowedIP)
			req.RemoteAddr = allowedIP + ":12345"
			
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}
			
			w := httptest.NewRecorder()
			suite.router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			
			if tt.expectRedirect {
				location := w.Header().Get("Location")
				assert.Equal(t, tt.redirectURL, location)
			} else {
				assert.Contains(t, w.Body.String(), "Admin Login")
			}
		})
	}
}

func (suite *TestAuthAccessSuite) testProductionLogin(t *testing.T) {
	allowedIP := "192.168.1.100"

	t.Run("Valid credentials should return JWT token", func(t *testing.T) {
		loginData := LoginRequest{
			Username: "admin",
			Password: "admin123",
		}
		
		jsonData, _ := json.Marshal(loginData)
		req := httptest.NewRequest("POST", "/admin/auth/login", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", allowedIP)
		req.RemoteAddr = allowedIP + ":12345"
		
		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
		
		var response LoginResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		
		assert.NotEmpty(t, response.Token)
		assert.Equal(t, "admin", response.User.Username)
		assert.Equal(t, "admin", response.User.Role)
		assert.True(t, response.ExpiresAt > time.Now().Unix())
	})

	t.Run("Invalid credentials should return error", func(t *testing.T) {
		loginData := LoginRequest{
			Username: "admin",
			Password: "wrongpassword",
		}
		
		jsonData, _ := json.Marshal(loginData)
		req := httptest.NewRequest("POST", "/admin/auth/login", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", allowedIP)
		req.RemoteAddr = allowedIP + ":12345"
		
		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		assert.Equal(t, 401, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid credentials")
	})

	t.Run("Login from non-whitelisted IP should be blocked", func(t *testing.T) {
		loginData := LoginRequest{
			Username: "admin",
			Password: "admin123",
		}
		
		jsonData, _ := json.Marshal(loginData)
		req := httptest.NewRequest("POST", "/admin/auth/login", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", "203.0.113.1")
		req.RemoteAddr = "203.0.113.1:12345"
		
		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		assert.Equal(t, 403, w.Code)
		assert.Contains(t, w.Body.String(), "Access denied: IP not authorized")
	})
}

func (suite *TestAuthAccessSuite) testProductionRedirects(t *testing.T) {
	allowedIP := "192.168.1.100"

	t.Run("Dashboard access with valid token should succeed", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/admin/dashboard", nil)
		req.Header.Set("Authorization", "Bearer "+suite.testToken)
		req.Header.Set("X-Forwarded-For", allowedIP)
		req.RemoteAddr = allowedIP + ":12345"
		
		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
		assert.Contains(t, w.Body.String(), "dashboard")
	})

	t.Run("Dashboard access without token should return 401", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/admin/dashboard", nil)
		req.Header.Set("X-Forwarded-For", allowedIP)
		req.RemoteAddr = allowedIP + ":12345"
		
		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		assert.Equal(t, 401, w.Code)
		assert.Contains(t, w.Body.String(), "Authorization token required")
	})

	t.Run("Dashboard access with expired token should return 401", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/admin/dashboard", nil)
		req.Header.Set("Authorization", "Bearer "+suite.expiredToken)
		req.Header.Set("X-Forwarded-For", allowedIP)
		req.RemoteAddr = allowedIP + ":12345"
		
		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		assert.Equal(t, 401, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid or expired token")
	})
}

func (suite *TestAuthAccessSuite) testModeBypass(t *testing.T) {
	nonWhitelistedIP := "203.0.113.1"

	t.Run("Test mode should bypass IP whitelist for main admin route", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/admin", nil)
		req.Header.Set("X-Forwarded-For", nonWhitelistedIP)
		req.RemoteAddr = nonWhitelistedIP + ":12345"
		
		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
		assert.Contains(t, w.Body.String(), "Admin Login")
	})

	t.Run("Test mode should bypass JWT for dashboard access", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/admin/dashboard", nil)
		req.Header.Set("X-Forwarded-For", nonWhitelistedIP)
		req.RemoteAddr = nonWhitelistedIP + ":12345"
		// No JWT token provided
		
		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
		assert.Contains(t, w.Body.String(), "dashboard")
	})

	t.Run("Test mode should allow login from any IP", func(t *testing.T) {
		loginData := LoginRequest{
			Username: "admin",
			Password: "admin123",
		}
		
		jsonData, _ := json.Marshal(loginData)
		req := httptest.NewRequest("POST", "/admin/auth/login", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", nonWhitelistedIP)
		req.RemoteAddr = nonWhitelistedIP + ":12345"
		
		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
		
		var response LoginResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.NotEmpty(t, response.Token)
	})
}

func (suite *TestAuthAccessSuite) testModeCredentials(t *testing.T) {
	t.Run("Test mode should generate random credentials", func(t *testing.T) {
		assert.NotNil(t, suite.authManager.testModeCredentials)
		assert.NotEmpty(t, suite.authManager.testModeCredentials.Username)
		assert.NotEmpty(t, suite.authManager.testModeCredentials.Password)
		
		// Username should start with admin_
		assert.True(t, strings.HasPrefix(suite.authManager.testModeCredentials.Username, "admin_"))
		
		// Password should be hex string
		assert.Regexp(t, "^[a-f0-9]+$", suite.authManager.testModeCredentials.Password)
	})

	t.Run("Test mode credentials should work for login", func(t *testing.T) {
		creds := suite.authManager.testModeCredentials
		loginData := LoginRequest{
			Username: creds.Username,
			Password: creds.Password,
		}
		
		jsonData, _ := json.Marshal(loginData)
		req := httptest.NewRequest("POST", "/admin/auth/login", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", "203.0.113.1")
		req.RemoteAddr = "203.0.113.1:12345"
		
		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
		
		var response LoginResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.NotEmpty(t, response.Token)
		assert.Equal(t, creds.Username, response.User.Username)
	})

	t.Run("Regular admin credentials should still work in test mode", func(t *testing.T) {
		loginData := LoginRequest{
			Username: "admin",
			Password: "admin123",
		}
		
		jsonData, _ := json.Marshal(loginData)
		req := httptest.NewRequest("POST", "/admin/auth/login", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", "203.0.113.1")
		req.RemoteAddr = "203.0.113.1:12345"
		
		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
		
		var response LoginResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.NotEmpty(t, response.Token)
		assert.Equal(t, "admin", response.User.Username)
	})
}

// Benchmark tests for performance validation
func BenchmarkAdminAccessControl(b *testing.B) {
	// Create a minimal test setup for benchmarking
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	jwtSecret := "test-jwt-secret-key-for-testing"
	allowedIPs := []string{"192.168.1.100", "10.0.0.50"}
	
	authManager := NewAuthManager(jwtSecret, logger)
	
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/admin", authManager.AdminAccessMiddleware(allowedIPs, "production"))
	
	adminGroup := router.Group("/admin")
	adminGroup.Use(authManager.RateLimitMiddleware())
	
	dashboardGroup := adminGroup.Group("/dashboard")
	dashboardGroup.Use(authManager.IPWhitelistMiddleware(allowedIPs, "production"))
	dashboardGroup.Use(authManager.JWTAuthMiddleware("production"))
	dashboardGroup.GET("", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "dashboard"})
	})
	
	// Generate valid test token
	claims := &AdminClaims{
		Username: "admin",
		Role:     "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "otp-service-admin",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	validToken, _ := token.SignedString([]byte(jwtSecret))
	
	b.Run("IPWhitelistCheck", func(b *testing.B) {
		req := httptest.NewRequest("GET", "/admin", nil)
		req.Header.Set("X-Forwarded-For", "192.168.1.100")
		req.RemoteAddr = "192.168.1.100:12345"
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
		}
	})

	b.Run("JWTValidation", func(b *testing.B) {
		req := httptest.NewRequest("GET", "/admin/dashboard", nil)
		req.Header.Set("Authorization", "Bearer "+validToken)
		req.Header.Set("X-Forwarded-For", "192.168.1.100")
		req.RemoteAddr = "192.168.1.100:12345"
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
		}
	})
}

// Edge case tests
func TestAdminAccessEdgeCases(t *testing.T) {
	suite := setupTestAuthSuite(t, "production")

	t.Run("Malformed JWT token should be rejected", func(t *testing.T) {
		malformedTokens := []string{
			"not.a.jwt",
			"Bearer invalid",
			strings.Repeat("a", 1000), // Very long token
			"",
			" ",
		}

		for _, token := range malformedTokens {
			req := httptest.NewRequest("GET", "/admin/dashboard", nil)
			if token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
			}
			req.Header.Set("X-Forwarded-For", "192.168.1.100")
			req.RemoteAddr = "192.168.1.100:12345"
			
			w := httptest.NewRecorder()
			suite.router.ServeHTTP(w, req)

			assert.Equal(t, 401, w.Code, "Token: %s", token)
		}
	})

	t.Run("Rate limiting should work", func(t *testing.T) {
		// This is a basic test - in real scenarios you'd test the actual rate limits
		req := httptest.NewRequest("GET", "/admin/auth/login", nil)
		req.Header.Set("X-Forwarded-For", "192.168.1.100")
		req.RemoteAddr = "192.168.1.100:12345"
		
		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		// First request should succeed (method not allowed but not rate limited)
		assert.NotEqual(t, 429, w.Code)
	})

	t.Run("Token in different locations should work", func(t *testing.T) {
		testCases := []struct {
			name     string
			setToken func(*http.Request)
		}{
			{
				name: "Authorization header",
				setToken: func(req *http.Request) {
					req.Header.Set("Authorization", "Bearer "+suite.testToken)
				},
			},
			{
				name: "Query parameter", 
				setToken: func(req *http.Request) {
					req.URL.RawQuery = "token=" + suite.testToken
				},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				req := httptest.NewRequest("GET", "/admin/dashboard", nil)
				tc.setToken(req)
				req.Header.Set("X-Forwarded-For", "192.168.1.100")
				req.RemoteAddr = "192.168.1.100:12345"
				
				w := httptest.NewRecorder()
				suite.router.ServeHTTP(w, req)

				assert.Equal(t, 200, w.Code)
			})
		}
	})
}