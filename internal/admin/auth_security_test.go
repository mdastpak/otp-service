package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestSecurityVulnerabilities(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel) // Reduce noise in tests
	
	authManager := NewAuthManager("test-secret", logger)
	
	t.Run("DoS Protection - Long Authorization Header", func(t *testing.T) {
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.Use(authManager.JWTAuthMiddleware("release"))
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// Create malicious header with excessive length (>1024 chars)
		maliciousHeader := "Bearer " + strings.Repeat("x", 1050)
		
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", maliciousHeader)
		
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		
		// Should be rejected due to length validation
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "Authorization token required")
	})
	
	t.Run("DoS Protection - Many Spaces in Header", func(t *testing.T) {
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.Use(authManager.JWTAuthMiddleware("release"))
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// Create header with many spaces to trigger the original strings.Split vulnerability
		maliciousHeader := "Bearer" + strings.Repeat(" ", 500) + "token"
		
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", maliciousHeader)
		
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		
		// Should be rejected due to format validation
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
	
	t.Run("Token Length Validation", func(t *testing.T) {
		// Test with excessively long token
		longToken := strings.Repeat("x", 600)
		
		_, err := authManager.validateToken(longToken)
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token too long")
	})
	
	t.Run("Empty Token Validation", func(t *testing.T) {
		_, err := authManager.validateToken("")
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "empty token")
	})
	
	t.Run("Malformed Token Handling", func(t *testing.T) {
		malformedTokens := []string{
			"not.a.jwt",
			"header.payload", // Missing signature
			".",
			"...",
			strings.Repeat(".", 100), // Many dots (original vulnerability)
		}
		
		for _, token := range malformedTokens {
			_, err := authManager.validateToken(token)
			assert.Error(t, err, "Should reject malformed token: %s", token)
		}
	})
	
	t.Run("Algorithm Confusion Attack Prevention", func(t *testing.T) {
		// This test ensures we only accept HMAC signing methods
		// In a real attack, this would be a token with "none" algorithm or RSA
		
		// Create a token with invalid signing method (this would fail in our validation)
		invalidToken := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6InRlc3QifQ."
		
		_, err := authManager.validateToken(invalidToken)
		assert.Error(t, err)
	})
	
	t.Run("Token with Spaces Rejection", func(t *testing.T) {
		gin.SetMode(gin.TestMode)
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest("GET", "/", nil)
		
		// Test query parameter with spaces
		c.Request.URL.RawQuery = "token=invalid token with spaces"
		token := authManager.extractToken(c)
		assert.Empty(t, token, "Should reject token with spaces")
		
		// Test cookie with spaces  
		c.Request.AddCookie(&http.Cookie{Name: "admin_token", Value: "invalid token"})
		token = authManager.extractToken(c)
		assert.Empty(t, token, "Should reject cookie token with spaces")
	})
}

func TestSecureTokenExtraction(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	authManager := NewAuthManager("test-secret", logger)
	
	t.Run("Valid Bearer Token Extraction", func(t *testing.T) {
		gin.SetMode(gin.TestMode)
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest("GET", "/", nil)
		c.Request.Header.Set("Authorization", "Bearer validtoken123")
		
		token := authManager.extractToken(c)
		assert.Equal(t, "validtoken123", token)
	})
	
	t.Run("Reject Invalid Bearer Format", func(t *testing.T) {
		gin.SetMode(gin.TestMode)
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest("GET", "/", nil)
		
		invalidFormats := []string{
			"Bearer",           // No token
			"Bearer ",          // Empty token
			"Bearertoken123",   // No space
			"Basic dXNlcjpwYXNz", // Wrong auth type
		}
		
		for _, format := range invalidFormats {
			c.Request.Header.Set("Authorization", format)
			token := authManager.extractToken(c)
			assert.Empty(t, token, "Should reject format: %s", format)
		}
	})
}

func BenchmarkSecureTokenExtraction(b *testing.B) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	authManager := NewAuthManager("test-secret", logger)
	
	b.Run("Normal Token", func(b *testing.B) {
		gin.SetMode(gin.TestMode)
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest("GET", "/", nil)
		c.Request.Header.Set("Authorization", "Bearer normaltoken123")
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = authManager.extractToken(c)
		}
	})
	
	b.Run("Long Header Attack", func(b *testing.B) {
		gin.SetMode(gin.TestMode)
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest("GET", "/", nil)
		
		// Simulate DoS attempt with long header
		longHeader := "Bearer " + strings.Repeat("x", 2000)
		c.Request.Header.Set("Authorization", longHeader)
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = authManager.extractToken(c)
		}
	})
}