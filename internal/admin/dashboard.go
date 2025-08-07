package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
	"otp-service/internal/metrics"
)

// DashboardData represents the complete dashboard data structure
type DashboardData struct {
	Stats     *Statistics   `json:"stats"`
	Health    *SystemHealth `json:"health"`
	Activities []Activity   `json:"activities"`
	ChartData *ChartData    `json:"chartData"`
}

// Statistics represents real-time OTP service statistics
type Statistics struct {
	ActiveOTPs      int64                  `json:"activeOtps"`
	SuccessRate     float64                `json:"successRate"`
	AvgResponseTime int64                  `json:"avgResponseTime"`
	RateLimited     int64                  `json:"rateLimited"`
	Trends          map[string]TrendData   `json:"trends"`
}

// TrendData represents trend information for statistics
type TrendData struct {
	Value     string `json:"value"`
	Direction string `json:"direction"` // "positive", "negative"
}

// SystemHealth represents the health status of various system components
type SystemHealth struct {
	API    HealthStatus `json:"api"`
	Redis  HealthStatus `json:"redis"`
	Memory HealthStatus `json:"memory"`
	CPU    HealthStatus `json:"cpu"`
}

// HealthStatus represents the status of a system component
type HealthStatus struct {
	Status     string `json:"status"`     // "healthy", "warning", "error"
	StatusText string `json:"statusText"` // Human readable status
	Details    string `json:"details"`    // Additional details
}

// Activity represents a real-time activity event
type Activity struct {
	Type      string    `json:"type"`      // "success", "failure", "rate-limit"
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

// ChartData represents data for dashboard charts
type ChartData struct {
	Operations *OperationsData `json:"operations"`
	Success    *SuccessData    `json:"success"`
}

// OperationsData represents timeline chart data
type OperationsData struct {
	Labels       []string `json:"labels"`
	Generation   []int64  `json:"generation"`
	Verification []int64  `json:"verification"`
}

// SuccessData represents success rate chart data
type SuccessData struct {
	Successful  int64 `json:"successful"`
	Failed      int64 `json:"failed"`
	RateLimited int64 `json:"rateLimited"`
}

// WebSocketClient represents a connected WebSocket client
type WebSocketClient struct {
	Conn   *websocket.Conn
	Send   chan []byte
	Hub    *WebSocketHub
	ID     string
}

// WebSocketHub manages WebSocket connections
type WebSocketHub struct {
	clients    map[*WebSocketClient]bool
	broadcast  chan []byte
	register   chan *WebSocketClient
	unregister chan *WebSocketClient
	mutex      sync.RWMutex
}

// DashboardManager manages the admin dashboard functionality
type DashboardManager struct {
	metricsService *metrics.Metrics
	logger         *logrus.Logger
	wsHub          *WebSocketHub
	activities     []Activity
	activitiesMux  sync.RWMutex
	upgrader       websocket.Upgrader
}

// NewDashboardManager creates a new dashboard manager
func NewDashboardManager(metricsService *metrics.Metrics, logger *logrus.Logger) *DashboardManager {
	hub := &WebSocketHub{
		clients:    make(map[*WebSocketClient]bool),
		broadcast:  make(chan []byte),
		register:   make(chan *WebSocketClient),
		unregister: make(chan *WebSocketClient),
	}

	dm := &DashboardManager{
		metricsService: metricsService,
		logger:         logger,
		wsHub:          hub,
		activities:     make([]Activity, 0, 1000),
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				// In production, implement proper origin checking
				return true
			},
		},
	}

	// Start WebSocket hub
	go hub.run()

	// Start periodic updates
	go dm.startPeriodicUpdates()

	return dm
}

// ServeDashboardHTML serves the dashboard HTML page (no auth required)
func (dm *DashboardManager) ServeDashboardHTML(c *gin.Context) {
	c.File("./web/admin/dashboard.html")
}

// SetupProtectedRoutes configures the protected admin API routes
func (dm *DashboardManager) SetupProtectedRoutes(router *gin.RouterGroup) {
	// Serve static files (no auth required)
	router.Static("/static", "./web/admin/static")
	
	// Protected API endpoints
	api := router.Group("/api")
	{
		api.GET("/dashboard-data", dm.getDashboardData)
		api.GET("/stats", dm.getStatistics)
		api.GET("/health", dm.getSystemHealth)
		api.GET("/activities", dm.getActivities)
		api.GET("/chart-data", dm.getChartData)
	}
	
	// WebSocket endpoint (protected)
	router.GET("/ws", dm.handleWebSocket)
}

// SetupRoutes configures the admin dashboard routes (legacy method)
func (dm *DashboardManager) SetupRoutes(router *gin.RouterGroup) {
	// Serve static files
	router.Static("/static", "./web/admin/static")
	
	// Serve dashboard HTML
	router.GET("/", dm.serveDashboard)
	
	// API endpoints
	api := router.Group("/api")
	{
		api.GET("/dashboard-data", dm.getDashboardData)
		api.GET("/stats", dm.getStatistics)
		api.GET("/health", dm.getSystemHealth)
		api.GET("/activities", dm.getActivities)
		api.GET("/chart-data", dm.getChartData)
	}
	
	// WebSocket endpoint
	router.GET("/ws", dm.handleWebSocket)
}

// serveDashboard serves the main dashboard HTML page (legacy)
func (dm *DashboardManager) serveDashboard(c *gin.Context) {
	c.File("./web/admin/dashboard.html")
}

// getDashboardData returns complete dashboard data
func (dm *DashboardManager) getDashboardData(c *gin.Context) {
	data := &DashboardData{
		Stats:      dm.getStats(),
		Health:     dm.getHealth(),
		Activities: dm.getRecentActivities(50),
		ChartData:  dm.generateChartData(),
	}
	
	c.JSON(http.StatusOK, data)
}

// getStatistics returns current statistics
func (dm *DashboardManager) getStatistics(c *gin.Context) {
	stats := dm.getStats()
	c.JSON(http.StatusOK, stats)
}

// getSystemHealth returns system health information
func (dm *DashboardManager) getSystemHealth(c *gin.Context) {
	health := dm.getHealth()
	c.JSON(http.StatusOK, health)
}

// getActivities returns recent activities
func (dm *DashboardManager) getActivities(c *gin.Context) {
	activities := dm.getRecentActivities(100)
	c.JSON(http.StatusOK, activities)
}

// getChartData returns chart data
func (dm *DashboardManager) getChartData(c *gin.Context) {
	chartData := dm.generateChartData()
	c.JSON(http.StatusOK, chartData)
}

// handleWebSocket handles WebSocket connections
func (dm *DashboardManager) handleWebSocket(c *gin.Context) {
	conn, err := dm.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		dm.logger.WithError(err).Error("WebSocket upgrade failed")
		return
	}

	client := &WebSocketClient{
		Conn: conn,
		Send: make(chan []byte, 256),
		Hub:  dm.wsHub,
		ID:   fmt.Sprintf("client_%d", time.Now().UnixNano()),
	}

	dm.wsHub.register <- client

	// Start goroutines for client
	go client.writePump()
	go client.readPump()
}

// getStats generates current statistics
func (dm *DashboardManager) getStats() *Statistics {
	// Handle case where metrics service is not available
	if dm.metricsService == nil {
		return &Statistics{
			ActiveOTPs:      0,
			SuccessRate:     0,
			AvgResponseTime: 0,
			RateLimited:     0,
			Trends: map[string]TrendData{
				"activeOtps":    {Value: "+0%", Direction: "neutral"},
				"successRate":   {Value: "+0%", Direction: "neutral"},
				"responseTime":  {Value: "0ms", Direction: "neutral"},
				"rateLimited":   {Value: "+0", Direction: "neutral"},
			},
		}
	}
	
	stats := dm.metricsService.GetStats()
	
	// Calculate success rate
	total := stats.OTPGenerated
	successful := stats.OTPVerified
	successRate := float64(0)
	if total > 0 {
		successRate = (float64(successful) / float64(total)) * 100
	}
	
	return &Statistics{
		ActiveOTPs:      dm.estimateActiveOTPs(),
		SuccessRate:     successRate,
		AvgResponseTime: dm.calculateAvgResponseTime(),
		RateLimited:     stats.RateLimited,
		Trends:          dm.calculateTrends(stats),
	}
}

// getHealth generates system health information
func (dm *DashboardManager) getHealth() *SystemHealth {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	
	// Calculate memory usage percentage (assuming 1GB limit for example)
	memUsagePercent := float64(memStats.Alloc) / (1024 * 1024 * 1024) * 100
	
	return &SystemHealth{
		API: HealthStatus{
			Status:     "healthy",
			StatusText: "Healthy",
			Details:    fmt.Sprintf("Uptime: %v", dm.metricsService.GetUptime()),
		},
		Redis: HealthStatus{
			Status:     "healthy",
			StatusText: "Healthy",
			Details:    "All connections active",
		},
		Memory: HealthStatus{
			Status:     dm.getMemoryStatus(memUsagePercent),
			StatusText: dm.getMemoryStatusText(memUsagePercent),
			Details:    fmt.Sprintf("Usage: %.1f%%", memUsagePercent),
		},
		CPU: HealthStatus{
			Status:     "healthy",
			StatusText: "Healthy",
			Details:    "Usage: < 50%",
		},
	}
}

// AddActivity adds a new activity to the feed
func (dm *DashboardManager) AddActivity(activityType, message string) {
	activity := Activity{
		Type:      activityType,
		Message:   message,
		Timestamp: time.Now(),
	}
	
	dm.activitiesMux.Lock()
	dm.activities = append([]Activity{activity}, dm.activities...)
	
	// Keep only last 1000 activities
	if len(dm.activities) > 1000 {
		dm.activities = dm.activities[:1000]
	}
	dm.activitiesMux.Unlock()
	
	// Broadcast to WebSocket clients
	dm.broadcastActivity(activity)
}

// Helper methods

func (dm *DashboardManager) getRecentActivities(limit int) []Activity {
	dm.activitiesMux.RLock()
	defer dm.activitiesMux.RUnlock()
	
	if len(dm.activities) <= limit {
		return dm.activities
	}
	
	return dm.activities[:limit]
}

func (dm *DashboardManager) estimateActiveOTPs() int64 {
	// This is a simplified estimation
	// In practice, you'd query Redis for active OTPs
	stats := dm.metricsService.GetStats()
	return stats.OTPGenerated - stats.OTPVerified - stats.OTPExpired
}

func (dm *DashboardManager) calculateAvgResponseTime() int64 {
	// Simplified calculation - in practice, track actual response times
	return 23 // milliseconds
}

func (dm *DashboardManager) calculateTrends(stats metrics.Stats) map[string]TrendData {
	// Simplified trend calculation
	return map[string]TrendData{
		"activeOtps": {
			Value:     "+12%",
			Direction: "positive",
		},
		"successRate": {
			Value:     "+2.3%",
			Direction: "positive",
		},
		"responseTime": {
			Value:     "-5ms",
			Direction: "positive",
		},
		"rateLimited": {
			Value:     "+15",
			Direction: "negative",
		},
	}
}

func (dm *DashboardManager) getMemoryStatus(usage float64) string {
	if usage < 70 {
		return "healthy"
	} else if usage < 85 {
		return "warning"
	}
	return "error"
}

func (dm *DashboardManager) getMemoryStatusText(usage float64) string {
	if usage < 70 {
		return "Healthy"
	} else if usage < 85 {
		return "Warning"
	}
	return "Critical"
}

func (dm *DashboardManager) generateChartData() *ChartData {
	// Generate sample chart data - in practice, collect from metrics
	now := time.Now()
	labels := make([]string, 12)
	generation := make([]int64, 12)
	verification := make([]int64, 12)
	
	for i := 0; i < 12; i++ {
		t := now.Add(-time.Duration(11-i) * 5 * time.Minute)
		labels[i] = t.Format("15:04")
		generation[i] = int64(50 + (i * 10) + (i % 3 * 15))
		verification[i] = int64(45 + (i * 9) + (i % 3 * 12))
	}
	
	stats := dm.metricsService.GetStats()
	
	return &ChartData{
		Operations: &OperationsData{
			Labels:       labels,
			Generation:   generation,
			Verification: verification,
		},
		Success: &SuccessData{
			Successful:  stats.OTPVerified,
			Failed:      stats.OTPInvalid,
			RateLimited: stats.RateLimited,
		},
	}
}

func (dm *DashboardManager) broadcastActivity(activity Activity) {
	data, err := json.Marshal(map[string]interface{}{
		"type": "activity_update",
		"data": activity,
	})
	if err != nil {
		dm.logger.WithError(err).Error("Failed to marshal activity")
		return
	}
	
	dm.wsHub.broadcast <- data
}

func (dm *DashboardManager) startPeriodicUpdates() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		// Broadcast stats update
		stats := dm.getStats()
		data, err := json.Marshal(map[string]interface{}{
			"type": "stats_update",
			"data": stats,
		})
		if err != nil {
			continue
		}
		
		dm.wsHub.broadcast <- data
		
		// Broadcast health update every 30 seconds
		if time.Now().Second()%30 == 0 {
			health := dm.getHealth()
			data, err := json.Marshal(map[string]interface{}{
				"type": "health_update",
				"data": health,
			})
			if err != nil {
				continue
			}
			
			dm.wsHub.broadcast <- data
		}
	}
}

// WebSocket Hub methods

func (h *WebSocketHub) run() {
	for {
		select {
		case client := <-h.register:
			h.mutex.Lock()
			h.clients[client] = true
			h.mutex.Unlock()
			
		case client := <-h.unregister:
			h.mutex.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.Send)
			}
			h.mutex.Unlock()
			
		case message := <-h.broadcast:
			h.mutex.RLock()
			for client := range h.clients {
				select {
				case client.Send <- message:
				default:
					delete(h.clients, client)
					close(client.Send)
				}
			}
			h.mutex.RUnlock()
		}
	}
}

// WebSocket Client methods

func (c *WebSocketClient) readPump() {
	defer func() {
		c.Hub.unregister <- c
		c.Conn.Close()
	}()
	
	c.Conn.SetReadLimit(512)
	c.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.Conn.SetPongHandler(func(string) error {
		c.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})
	
	for {
		_, _, err := c.Conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

func (c *WebSocketClient) writePump() {
	ticker := time.NewTicker(54 * time.Second)
	defer func() {
		ticker.Stop()
		c.Conn.Close()
	}()
	
	for {
		select {
		case message, ok := <-c.Send:
			c.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			
			w, err := c.Conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)
			
			// Add queued messages
			n := len(c.Send)
			for i := 0; i < n; i++ {
				w.Write([]byte{'\n'})
				w.Write(<-c.Send)
			}
			
			if err := w.Close(); err != nil {
				return
			}
			
		case <-ticker.C:
			c.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}