package admin

import (
	"crypto/subtle"
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
	// In production, load admin users from secure configuration
	adminUsers := map[string]string{
		"admin": "$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi", // password: "admin123"
	}
	
	return &AuthManager{
		jwtSecret:  []byte(jwtSecret),
		adminUsers: adminUsers,
		logger:     logger,
	}
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
		"admin": "admin123", // In production, use secure passwords
	})
}

// JWTAuthMiddleware provides JWT-based authentication
func (am *AuthManager) JWTAuthMiddleware() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		tokenString := am.extractToken(c)
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization token required",
			})
			c.Abort()
			return
		}

		claims, err := am.validateToken(tokenString)
		if err != nil {
			am.logger.WithError(err).Warn("Invalid admin token")
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid or expired token",
			})
			c.Abort()
			return
		}

		// Store user info in context
		c.Set("admin_user", claims.Username)
		c.Set("admin_role", claims.Role)
		c.Next()
	})
}

// IPWhitelistMiddleware restricts access to specific IP addresses
func (am *AuthManager) IPWhitelistMiddleware(allowedIPs []string) gin.HandlerFunc {
	allowedIPMap := make(map[string]bool)
	for _, ip := range allowedIPs {
		allowedIPMap[ip] = true
	}
	
	return gin.HandlerFunc(func(c *gin.Context) {
		clientIP := c.ClientIP()
		
		// Allow localhost and whitelisted IPs
		if clientIP == "127.0.0.1" || clientIP == "::1" || allowedIPMap[clientIP] {
			c.Next()
			return
		}
		
		am.logger.WithField("ip", clientIP).Warn("Admin access denied: IP not whitelisted")
		c.JSON(http.StatusForbidden, gin.H{
			"error": "Access denied: IP not authorized",
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
	// Check Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader != "" {
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 && parts[0] == "Bearer" {
			return parts[1]
		}
	}
	
	// Check query parameter
	token := c.Query("token")
	if token != "" {
		return token
	}
	
	// Check cookie
	cookie, err := c.Cookie("admin_token")
	if err == nil {
		return cookie
	}
	
	return ""
}

func (am *AuthManager) validateToken(tokenString string) (*AdminClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &AdminClaims{}, func(token *jwt.Token) (interface{}, error) {
		return am.jwtSecret, nil
	})
	
	if err != nil {
		return nil, err
	}
	
	if claims, ok := token.Claims.(*AdminClaims); ok && token.Valid {
		return claims, nil
	}
	
	return nil, errors.New("invalid token")
}

func (am *AuthManager) verifyCredentials(username, password string) bool {
	// In production, use proper password hashing (bcrypt)
	// For demo purposes, using simple comparison
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
                    // Store token and redirect
                    localStorage.setItem('admin_token', data.token);
                    window.location.href = '/admin/';
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

// ServeLoginPage serves the admin login page
func (am *AuthManager) ServeLoginPage(c *gin.Context) {
	c.Header("Content-Type", "text/html")
	c.String(http.StatusOK, am.CreateAdminLoginPage())
}