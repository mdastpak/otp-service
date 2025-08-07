package admin

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"
	"time"
	"errors"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
)

// AdminClaims represents JWT claims for admin authentication
type AdminClaims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// AuthManager handles admin authentication
type AuthManager struct {
	jwtSecret   []byte
	adminUsers  map[string]string // username -> password hash
	logger      *logrus.Logger
	testModeCredentials *TestCredentials // For test mode
}

// TestCredentials holds the randomly generated test mode credentials
type TestCredentials struct {
	Username string
	Password string
}

// LoginRequest represents a login request
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// LoginResponse represents a login response
type LoginResponse struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expiresAt"`
	User      User   `json:"user"`
}

// User represents an admin user
type User struct {
	Username string `json:"username"`
	Role     string `json:"role"`
}

// NewAuthManager creates a new authentication manager
func NewAuthManager(jwtSecret string, logger *logrus.Logger) *AuthManager {
	return newAuthManager(jwtSecret, logger, "")
}

// NewAuthManagerWithMode creates a new authentication manager with server mode
func NewAuthManagerWithMode(jwtSecret string, logger *logrus.Logger, serverMode string) *AuthManager {
	return newAuthManager(jwtSecret, logger, serverMode)
}

func newAuthManager(jwtSecret string, logger *logrus.Logger, serverMode string) *AuthManager {
	// In production, load admin users from secure configuration
	adminUsers := map[string]string{
		"admin": "$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi", // bcrypt hash of default password
	}
	
	am := &AuthManager{
		jwtSecret:  []byte(jwtSecret),
		adminUsers: adminUsers,
		logger:     logger,
	}
	
	// Generate random credentials for test mode
	if serverMode == "test" {
		creds := generateTestCredentials()
		am.testModeCredentials = creds
		logger.WithFields(logrus.Fields{
			"username": creds.Username,
			"password": creds.Password,
			"mode":     "test",
		}).Info("🔧 Test mode admin credentials generated")
	}
	
	return am
}

// SetupAuthRoutes configures authentication routes
func (am *AuthManager) SetupAuthRoutes(router *gin.RouterGroup) {
	router.POST("/login", am.login)
	router.POST("/logout", am.logout)
	router.GET("/verify", am.verifyToken)
}

// BasicAuthMiddleware provides basic HTTP authentication for admin access
func (am *AuthManager) BasicAuthMiddleware() gin.HandlerFunc {
	return gin.BasicAuth(gin.Accounts{
		"admin": "admin123", // TODO: Load from secure configuration in production
	})
}

// JWTAuthMiddleware provides JWT-based authentication
func (am *AuthManager) JWTAuthMiddleware(serverMode string) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		clientIP := c.ClientIP()
		userAgent := c.GetHeader("User-Agent")
		requestURI := c.Request.RequestURI
		method := c.Request.Method
		
		// Bypass JWT validation in test mode
		if serverMode == "test" {
			am.logger.WithFields(logrus.Fields{
				"ip":           clientIP,
				"user_agent":   userAgent,
				"request_uri":  requestURI,
				"method":       method,
				"mode":         "test",
			}).Info("Admin JWT auth bypassed in test mode")
			
			// Set default admin context in test mode
			c.Set("admin_user", "test_admin")
			c.Set("admin_role", "admin")
			c.Next()
			return
		}
		
		tokenString := am.extractToken(c)
		if tokenString == "" {
			am.logger.WithFields(logrus.Fields{
				"ip":           clientIP,
				"user_agent":   userAgent,
				"request_uri":  requestURI,
				"method":       method,
				"error":        "missing_token",
			}).Warn("Admin JWT auth failed: missing token")
			
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":        "Authorization token required",
				"requested_ip": clientIP,
				"user_agent":   userAgent,
				"request_uri":  requestURI,
				"method":       method,
				"timestamp":    time.Now().UTC().Format(time.RFC3339),
			})
			c.Abort()
			return
		}

		claims, err := am.validateToken(tokenString)
		if err != nil {
			am.logger.WithFields(logrus.Fields{
				"ip":           clientIP,
				"user_agent":   userAgent,
				"request_uri":  requestURI,
				"method":       method,
				"error":        err.Error(),
			}).Warn("Admin JWT auth failed: invalid token")
			
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":        "Invalid or expired token",
				"requested_ip": clientIP,
				"user_agent":   userAgent,
				"request_uri":  requestURI,
				"method":       method,
				"timestamp":    time.Now().UTC().Format(time.RFC3339),
			})
			c.Abort()
			return
		}

		am.logger.WithFields(logrus.Fields{
			"ip":           clientIP,
			"user_agent":   userAgent,
			"request_uri":  requestURI,
			"method":       method,
			"admin_user":   claims.Username,
			"admin_role":   claims.Role,
		}).Info("Admin JWT auth successful")

		// Store user info in context
		c.Set("admin_user", claims.Username)
		c.Set("admin_role", claims.Role)
		c.Next()
	})
}

// IPWhitelistMiddleware restricts access to specific IP addresses
func (am *AuthManager) IPWhitelistMiddleware(allowedIPs []string, serverMode string) gin.HandlerFunc {
	allowedIPMap := make(map[string]bool)
	for _, ip := range allowedIPs {
		allowedIPMap[ip] = true
	}
	
	return gin.HandlerFunc(func(c *gin.Context) {
		clientIP := c.ClientIP()
		userAgent := c.GetHeader("User-Agent")
		requestURI := c.Request.RequestURI
		method := c.Request.Method
		
		// Bypass IP validation in test mode
		if serverMode == "test" {
			am.logger.WithFields(logrus.Fields{
				"ip":           clientIP,
				"user_agent":   userAgent,
				"request_uri":  requestURI,
				"method":       method,
				"mode":         "test",
			}).Info("Admin access allowed: IP validation bypassed in test mode")
			c.Next()
			return
		}
		
		// Allow localhost and whitelisted IPs
		if clientIP == "127.0.0.1" || clientIP == "::1" || allowedIPMap[clientIP] {
			am.logger.WithFields(logrus.Fields{
				"ip":           clientIP,
				"user_agent":   userAgent,
				"request_uri":  requestURI,
				"method":       method,
				"authorized":   true,
			}).Info("Admin access granted: IP authorized")
			c.Next()
			return
		}
		
		am.logger.WithFields(logrus.Fields{
			"ip":           clientIP,
			"user_agent":   userAgent,
			"request_uri":  requestURI,
			"method":       method,
			"allowed_ips":  allowedIPs,
			"authorized":   false,
		}).Warn("Admin access denied: IP not whitelisted")
		
		c.JSON(http.StatusForbidden, gin.H{
			"error":        "Access denied: IP not authorized",
			"requested_ip": clientIP,
			"user_agent":   userAgent,
			"request_uri":  requestURI,
			"method":       method,
			"timestamp":    time.Now().UTC().Format(time.RFC3339),
		})
		c.Abort()
	})
}

// RateLimitMiddleware provides rate limiting for admin endpoints
func (am *AuthManager) RateLimitMiddleware() gin.HandlerFunc {
	// Simple in-memory rate limiting - in production, use Redis
	requestCounts := make(map[string]int)
	lastReset := time.Now()
	
	return gin.HandlerFunc(func(c *gin.Context) {
		now := time.Now()
		clientIP := c.ClientIP()
		
		// Reset counts every minute
		if now.Sub(lastReset) > time.Minute {
			requestCounts = make(map[string]int)
			lastReset = now
		}
		
		// Check request count
		requestCounts[clientIP]++
		if requestCounts[clientIP] > 60 { // 60 requests per minute
			am.logger.WithField("ip", clientIP).Warn("Admin rate limit exceeded")
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Rate limit exceeded",
			})
			c.Abort()
			return
		}
		
		c.Next()
	})
}

// login handles admin login
func (am *AuthManager) login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	// Verify credentials
	if !am.verifyCredentials(req.Username, req.Password) {
		am.logger.WithField("username", req.Username).Warn("Failed admin login attempt")
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid credentials",
		})
		return
	}

	// Generate JWT token
	expiresAt := time.Now().Add(24 * time.Hour) // 24 hour expiry
	claims := AdminClaims{
		Username: req.Username,
		Role:     "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "otp-service-admin",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(am.jwtSecret)
	if err != nil {
		am.logger.WithError(err).Error("Failed to generate JWT token")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to generate token",
		})
		return
	}

	am.logger.WithField("username", req.Username).Info("Successful admin login")

	c.JSON(http.StatusOK, LoginResponse{
		Token:     tokenString,
		ExpiresAt: expiresAt.Unix(),
		User: User{
			Username: req.Username,
			Role:     "admin",
		},
	})
}

// logout handles admin logout
func (am *AuthManager) logout(c *gin.Context) {
	// In a production system, you might maintain a token blacklist
	am.logger.Info("Admin logout")
	c.JSON(http.StatusOK, gin.H{
		"message": "Logged out successfully",
	})
}

// verifyToken handles token verification
func (am *AuthManager) verifyToken(c *gin.Context) {
	tokenString := am.extractToken(c)
	if tokenString == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "No token provided",
		})
		return
	}

	claims, err := am.validateToken(tokenString)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid token",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"valid": true,
		"user": User{
			Username: claims.Username,
			Role:     claims.Role,
		},
	})
}

// Helper methods

func (am *AuthManager) extractToken(c *gin.Context) string {
	// Check Authorization header with length validation
	authHeader := c.GetHeader("Authorization")
	if authHeader != "" {
		// Prevent DoS attacks by limiting header length
		const maxHeaderLength = 1024
		if len(authHeader) > maxHeaderLength {
			am.logger.WithField("header_length", len(authHeader)).Warn("Authorization header too long, potential DoS attempt")
			return ""
		}
		
		// Use safer parsing instead of strings.Split to prevent excessive memory allocation
		const bearerPrefix = "Bearer "
		if len(authHeader) > len(bearerPrefix) && authHeader[:len(bearerPrefix)] == bearerPrefix {
			token := strings.TrimSpace(authHeader[len(bearerPrefix):])
			// Additional validation on token format to prevent further abuse
			if len(token) > 0 && len(token) <= 512 && !strings.Contains(token, " ") {
				return token
			}
		}
	}
	
	// Check query parameter with validation
	token := c.Query("token")
	if token != "" && len(token) <= 512 && !strings.Contains(token, " ") {
		return token
	}
	
	// Check cookie with validation
	cookie, err := c.Cookie("admin_token")
	if err == nil && len(cookie) <= 512 && !strings.Contains(cookie, " ") {
		return cookie
	}
	
	return ""
}

func (am *AuthManager) validateToken(tokenString string) (*AdminClaims, error) {
	// Additional input validation to prevent abuse
	if len(tokenString) == 0 {
		return nil, errors.New("empty token")
	}
	
	if len(tokenString) > 512 {
		am.logger.WithField("token_length", len(tokenString)).Warn("JWT token too long, potential DoS attempt")
		return nil, errors.New("token too long")
	}
	
	token, err := jwt.ParseWithClaims(tokenString, &AdminClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method to prevent algorithm confusion attacks
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return am.jwtSecret, nil
	})
	
	// Critical security fix: Handle errors properly according to JWT security advisory
	// Do not accept tokens with signature validation errors, even if other validations pass
	if err != nil {
		// Log the specific error for debugging but don't expose it
		am.logger.WithError(err).Warn("JWT validation failed")
		
		// Check for specific error types to provide appropriate responses
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, errors.New("token expired")
		}
		if errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, errors.New("token not valid yet")
		}
		if errors.Is(err, jwt.ErrTokenMalformed) {
			return nil, errors.New("token malformed")
		}
		
		// For any other error (including signature validation failures), 
		// return generic invalid token error to prevent information leakage
		return nil, errors.New("invalid token")
	}
	
	// Additional validation: ensure token is valid and claims are correct type
	claims, ok := token.Claims.(*AdminClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}
	
	if !token.Valid {
		return nil, errors.New("invalid token")
	}
	
	// Additional claims validation
	if claims.Username == "" {
		return nil, errors.New("invalid token: missing username")
	}
	
	if claims.Role == "" {
		return nil, errors.New("invalid token: missing role")
	}
	
	// Validate issuer if present
	if claims.Issuer != "" && claims.Issuer != "otp-service-admin" {
		return nil, errors.New("invalid token: incorrect issuer")
	}
	
	return claims, nil
}

func (am *AuthManager) verifyCredentials(username, password string) bool {
	// Check test mode credentials first
	if am.testModeCredentials != nil {
		if username == am.testModeCredentials.Username {
			return subtle.ConstantTimeCompare([]byte(password), []byte(am.testModeCredentials.Password)) == 1
		}
	}
	
	// Check regular admin users
	_, exists := am.adminUsers[username]
	if !exists {
		return false
	}
	
	// Use constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare([]byte(password), []byte("admin123")) == 1
}

// CreateAdminLoginPage creates a simple login page
func (am *AuthManager) CreateAdminLoginPage() string {
	return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OTP Service Admin Login</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0;
        }
        .login-container {
            background: white;
            padding: 2rem;
            border-radius: 10px;
            box-shadow: 0 15px 25px rgba(0,0,0,0.2);
            width: 100%;
            max-width: 400px;
        }
        .login-header {
            text-align: center;
            margin-bottom: 2rem;
        }
        .login-header h1 {
            color: #333;
            margin-bottom: 0.5rem;
        }
        .login-header p {
            color: #666;
            font-size: 0.9rem;
        }
        .form-group {
            margin-bottom: 1.5rem;
        }
        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            color: #333;
            font-weight: 500;
        }
        .form-group input {
            width: 100%;
            padding: 0.75rem;
            border: 2px solid #e1e5e9;
            border-radius: 5px;
            font-size: 1rem;
            transition: border-color 0.3s;
        }
        .form-group input:focus {
            outline: none;
            border-color: #667eea;
        }
        .login-btn {
            width: 100%;
            padding: 0.75rem;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 1rem;
            font-weight: 500;
            cursor: pointer;
            transition: background 0.3s;
        }
        .login-btn:hover {
            background: #5a6fd8;
        }
        .error-message {
            color: #e74c3c;
            font-size: 0.9rem;
            margin-top: 1rem;
            text-align: center;
            display: none;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <h1>🔐 Admin Login</h1>
            <p>OTP Service Administration Panel</p>
        </div>
        <form id="loginForm">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit" class="login-btn">Sign In</button>
            <div id="errorMessage" class="error-message"></div>
        </form>
    </div>

    <script>
        // Check if user is already logged in
        window.addEventListener('load', async () => {
            const token = localStorage.getItem('admin_token');
            if (token) {
                try {
                    const response = await fetch('/admin/auth/verify', {
                        method: 'GET',
                        headers: {
                            'Authorization': 'Bearer ' + token,
                            'Content-Type': 'application/json',
                        },
                    });
                    
                    if (response.ok) {
                        // Token is valid, redirect to dashboard
                        window.location.href = '/admin/dashboard';
                        return;
                    }
                } catch (error) {
                    // Token verification failed, remove invalid token
                    localStorage.removeItem('admin_token');
                }
            }
        });
        
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const errorDiv = document.getElementById('errorMessage');
            
            try {
                const response = await fetch('/admin/auth/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ username, password }),
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    // Store token and redirect to dashboard
                    localStorage.setItem('admin_token', data.token);
                    window.location.href = '/admin/dashboard';
                } else {
                    errorDiv.textContent = data.error || 'Login failed';
                    errorDiv.style.display = 'block';
                }
            } catch (error) {
                errorDiv.textContent = 'Network error. Please try again.';
                errorDiv.style.display = 'block';
            }
        });
    </script>
</body>
</html>
`
}

// generateTestCredentials creates random username and password for test mode
func generateTestCredentials() *TestCredentials {
	// Generate random username
	usernameSuffix := make([]byte, 4)
	rand.Read(usernameSuffix)
	username := fmt.Sprintf("admin_%x", usernameSuffix)
	
	// Generate random password
	passwordBytes := make([]byte, 8)
	rand.Read(passwordBytes)
	password := fmt.Sprintf("%x", passwordBytes)
	
	return &TestCredentials{
		Username: username,
		Password: password,
	}
}

// AdminAccessMiddleware handles /admin route access control
func (am *AuthManager) AdminAccessMiddleware(allowedIPs []string, serverMode string) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		clientIP := c.ClientIP()
		userAgent := c.GetHeader("User-Agent")
		requestURI := c.Request.RequestURI
		method := c.Request.Method
		
		// Step 1: Check IP whitelist (bypass in test mode)
		ipAllowed := serverMode == "test" || isIPAllowed(clientIP, allowedIPs)
		
		if !ipAllowed {
			// Log unauthorized access attempt
			am.logger.WithFields(logrus.Fields{
				"ip":           clientIP,
				"user_agent":   userAgent,
				"request_uri":  requestURI,
				"method":       method,
				"allowed_ips":  allowedIPs,
			}).Warn("Admin access denied: IP not whitelisted")
			
			// Show restriction message
			c.Header("Content-Type", "text/html")
			c.String(http.StatusForbidden, am.CreateRestrictionPage(clientIP))
			c.Abort()
			return
		}
		
		// Step 2: Check JWT token
		tokenString := am.extractToken(c)
		if tokenString != "" {
			claims, err := am.validateToken(tokenString)
			if err == nil {
				// Valid token - redirect to dashboard
				am.logger.WithFields(logrus.Fields{
					"ip":           clientIP,
					"user_agent":   userAgent,
					"admin_user":   claims.Username,
				}).Info("Admin access: valid token, redirecting to dashboard")
				
				c.Redirect(http.StatusFound, "/admin/dashboard")
				c.Abort()
				return
			}
		}
		
		// Step 3: No valid token but IP is allowed - show login page
		am.logger.WithFields(logrus.Fields{
			"ip":           clientIP,
			"user_agent":   userAgent,
			"request_uri":  requestURI,
			"method":       method,
		}).Info("Admin access: IP authorized, showing login page")
		
		c.Header("Content-Type", "text/html")
		c.String(http.StatusOK, am.CreateAdminLoginPage())
		c.Abort()
	})
}

// isIPAllowed checks if the client IP is in the allowed list or localhost
func isIPAllowed(clientIP string, allowedIPs []string) bool {
	// Always allow localhost
	if clientIP == "127.0.0.1" || clientIP == "::1" {
		return true
	}
	
	// Check whitelist
	for _, allowedIP := range allowedIPs {
		if clientIP == allowedIP {
			return true
		}
	}
	
	return false
}

// CreateRestrictionPage creates an HTML page for IP restriction
func (am *AuthManager) CreateRestrictionPage(clientIP string) string {
	return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Restricted - OTP Service</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #e74c3c 0%%, #c0392b 100%%);
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0;
        }
        .restriction-container {
            background: white;
            padding: 3rem;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.3);
            text-align: center;
            max-width: 500px;
            width: 90%%;
        }
        .restriction-icon {
            font-size: 4rem;
            margin-bottom: 1rem;
        }
        .restriction-title {
            color: #e74c3c;
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 1rem;
        }
        .restriction-message {
            color: #666;
            font-size: 1.1rem;
            line-height: 1.6;
            margin-bottom: 2rem;
        }
        .client-info {
            background: #f8f9fa;
            padding: 1.5rem;
            border-radius: 8px;
            border-left: 4px solid #e74c3c;
            margin: 1.5rem 0;
        }
        .client-info h3 {
            color: #333;
            margin-top: 0;
            font-size: 1.2rem;
        }
        .client-info p {
            color: #666;
            margin: 0.5rem 0;
            font-family: 'Courier New', monospace;
        }
        .contact-info {
            background: #e8f4fd;
            padding: 1.5rem;
            border-radius: 8px;
            margin-top: 2rem;
        }
        .contact-info h3 {
            color: #2980b9;
            margin-top: 0;
        }
        .footer {
            margin-top: 2rem;
            color: #999;
            font-size: 0.9rem;
        }
    </style>
</head>
<body>
    <div class="restriction-container">
        <div class="restriction-icon">🚫</div>
        <h1 class="restriction-title">Access Restricted</h1>
        <p class="restriction-message">
            Your IP address is not authorized to access the OTP Service Administration Panel.
            This security measure protects our system from unauthorized access.
        </p>
        
        <div class="client-info">
            <h3>🔍 Connection Information</h3>
            <p><strong>Your IP Address:</strong> %s</p>
            <p><strong>Access Attempt:</strong> %s</p>
            <p><strong>Status:</strong> Blocked</p>
        </div>
        
        <div class="contact-info">
            <h3>📞 Need Access?</h3>
            <p>If you believe you should have access to this system, please contact your system administrator to add your IP address to the whitelist.</p>
        </div>
        
        <div class="footer">
            <p>🔒 This access attempt has been logged for security purposes.</p>
        </div>
    </div>
</body>
</html>
`, clientIP, time.Now().UTC().Format("2006-01-02 15:04:05 UTC"))
}

// ServeLoginPage serves the admin login page
func (am *AuthManager) ServeLoginPage(c *gin.Context) {
	c.Header("Content-Type", "text/html")
	c.String(http.StatusOK, am.CreateAdminLoginPage())
}