// pkg/cache/monitor.go

package cache

import (
	"otp-service/pkg/logger"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type CacheMonitor struct {
	metrics    *CacheMetrics
	analyzer   *TTLAnalyzer
	calculator *CacheSizeCalculator
	cache      *LocalCache
	mu         sync.RWMutex

	// Prometheus metrics
	hitRatio    prometheus.Gauge
	cacheSize   prometheus.Gauge
	memoryUsage prometheus.Gauge
}

type CacheStats struct {
	HitRatio         float64   `json:"hit_ratio"`
	Hits             int64     `json:"hits"`
	Misses           int64     `json:"misses"`
	Evictions        int64     `json:"evictions"`
	CurrentSize      int       `json:"current_size"`
	MaxSize          int       `json:"max_size"`
	MemoryUsageBytes uint64    `json:"memory_usage_bytes"`
	LastUpdated      time.Time `json:"last_updated"`
	Recommendations  []string  `json:"recommendations,omitempty"`
}

func NewCacheMonitor(cache *LocalCache, metrics *CacheMetrics) *CacheMonitor {
	monitor := &CacheMonitor{
		metrics:    metrics,
		analyzer:   NewTTLAnalyzer(),
		calculator: NewCacheSizeCalculator(),
		cache:      cache,
		hitRatio: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "cache_hit_ratio",
			Help: "Cache hit ratio over the last minute",
		}),
		cacheSize: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "cache_size",
			Help: "Current number of items in cache",
		}),
		memoryUsage: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "cache_memory_usage_bytes",
			Help: "Estimated memory usage of cache",
		}),
	}

	prometheus.MustRegister(monitor.hitRatio)
	prometheus.MustRegister(monitor.cacheSize)
	prometheus.MustRegister(monitor.memoryUsage)

	go monitor.startMonitoring()
	return monitor
}

func (m *CacheMonitor) startMonitoring() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		m.updateMetrics()
		m.analyzePerformance()
		m.recommendOptimizations()
	}
}

func (m *CacheMonitor) updateMetrics() {
	totalRequests := float64(m.metrics.hits + m.metrics.misses)
	if totalRequests > 0 {
		hitRatio := float64(m.metrics.hits) / totalRequests
		m.hitRatio.Set(hitRatio)
	}

	m.cacheSize.Set(float64(len(m.cache.items)))

	// Estimate memory usage
	itemCount := len(m.cache.items)
	estimatedMemory := uint64(itemCount) * m.calculator.averageItemSize
	m.memoryUsage.Set(float64(estimatedMemory))
}

func (m *CacheMonitor) analyzePerformance() {
	hitRatio := float64(m.metrics.hits) / float64(m.metrics.hits+m.metrics.misses)

	// Log performance metrics
	logger.Info("Cache performance:",
		"hit_ratio", hitRatio,
		"total_hits", m.metrics.hits,
		"total_misses", m.metrics.misses,
		"evictions", m.metrics.evictions,
	)

	// Analyze if optimization is needed
	if hitRatio < 0.5 { // Hit ratio below 50%
		logger.Warn("Low cache hit ratio detected, consider adjusting cache size or TTL")
	}
}

func (m *CacheMonitor) recommendOptimizations() {
	// Calculate optimal cache size
	optimalSize, err := m.calculator.CalculateMaxSize()
	if err != nil {
		logger.Error("Failed to calculate optimal cache size:", err)
		return
	}

	currentSize := len(m.cache.items)
	if float64(currentSize) > float64(optimalSize)*0.9 { // Over 90% full
		logger.Warn("Cache approaching capacity, consider increasing max size or reducing TTL")
	}

	// Calculate optimal cleanup interval
	optimalInterval := m.analyzer.CalculateOptimalCleanupInterval()
	logger.Info("Recommended optimizations:",
		"optimal_size", optimalSize,
		"optimal_cleanup_interval", optimalInterval,
	)
}

func (m *CacheMonitor) GetStats() *CacheStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	totalRequests := float64(m.metrics.hits + m.metrics.misses)
	hitRatio := float64(0)
	if totalRequests > 0 {
		hitRatio = float64(m.metrics.hits) / totalRequests
	}

	currentSize := len(m.cache.items)
	stats := &CacheStats{
		HitRatio:         hitRatio,
		Hits:             m.metrics.hits,
		Misses:           m.metrics.misses,
		Evictions:        m.metrics.evictions,
		CurrentSize:      currentSize,
		MaxSize:          m.cache.maxSize,
		MemoryUsageBytes: uint64(currentSize) * m.calculator.averageItemSize,
		LastUpdated:      time.Now(),
		Recommendations:  m.generateRecommendations(),
	}

	return stats
}

func (m *CacheMonitor) generateRecommendations() []string {
	var recommendations []string

	// Hit ratio analysis
	hitRatio := float64(m.metrics.hits) / float64(m.metrics.hits+m.metrics.misses)
	if hitRatio < 0.5 {
		recommendations = append(recommendations,
			"Low cache hit ratio detected. Consider increasing cache size or adjusting TTL values.")
	}

	// Size analysis
	currentSize := len(m.cache.items)
	if float64(currentSize) > float64(m.cache.maxSize)*0.9 {
		recommendations = append(recommendations,
			"Cache is approaching capacity. Consider increasing max size or reducing TTL values.")
	}

	// Eviction analysis
	if m.metrics.evictions > 0 && float64(m.metrics.evictions)/float64(currentSize) > 0.1 {
		recommendations = append(recommendations,
			"High eviction rate detected. Consider increasing cache size.")
	}

	return recommendations
}
