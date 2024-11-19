// pkg/cache/cache.go

package cache

import (
	"sync"
	"time"

	"otp-service/pkg/logger"
)

type CacheItem struct {
	Value      interface{}
	ExpiresAt  time.Time
	AccessedAt time.Time
}

type LocalCache struct {
	items         map[string]*CacheItem
	mu            sync.RWMutex
	maxSize       int
	cleanupTicker *time.Ticker
	metrics       *CacheMetrics
}

type CacheMetrics struct {
	hits        int64
	misses      int64
	evictions   int64
	expirations int64
}

type Options struct {
	MaxSize         int
	CleanupInterval time.Duration
}

func NewLocalCache(opts Options) *LocalCache {
	if opts.MaxSize <= 0 {
		opts.MaxSize = 1000 // Default size
	}
	if opts.CleanupInterval <= 0 {
		opts.CleanupInterval = 5 * time.Minute // Default cleanup interval
	}

	cache := &LocalCache{
		items:         make(map[string]*CacheItem),
		maxSize:       opts.MaxSize,
		cleanupTicker: time.NewTicker(opts.CleanupInterval),
		metrics:       &CacheMetrics{},
	}

	go cache.startCleanup()
	return cache
}

func (c *LocalCache) Set(key string, value interface{}, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if we need to evict items
	if len(c.items) >= c.maxSize {
		c.evictOldest()
	}

	c.items[key] = &CacheItem{
		Value:      value,
		ExpiresAt:  time.Now().Add(ttl),
		AccessedAt: time.Now(),
	}
}

func (c *LocalCache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	item, exists := c.items[key]
	c.mu.RUnlock()

	if !exists {
		c.incrementMisses()
		return nil, false
	}

	// Check expiration
	if time.Now().After(item.ExpiresAt) {
		c.mu.Lock()
		delete(c.items, key)
		c.mu.Unlock()
		c.incrementExpirations()
		return nil, false
	}

	// Update access time
	c.mu.Lock()
	item.AccessedAt = time.Now()
	c.mu.Unlock()

	c.incrementHits()
	return item.Value, true
}

func (c *LocalCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, key)
}

func (c *LocalCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[string]*CacheItem)
}

func (c *LocalCache) evictOldest() {
	var oldestKey string
	var oldestAccess time.Time

	for key, item := range c.items {
		if oldestAccess.IsZero() || item.AccessedAt.Before(oldestAccess) {
			oldestKey = key
			oldestAccess = item.AccessedAt
		}
	}

	if oldestKey != "" {
		delete(c.items, oldestKey)
		c.metrics.evictions++
		logger.Debug("Cache item evicted:", oldestKey)
	}
}

func (c *LocalCache) startCleanup() {
	for range c.cleanupTicker.C {
		c.cleanup()
	}
}

func (c *LocalCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, item := range c.items {
		if now.After(item.ExpiresAt) {
			delete(c.items, key)
			c.metrics.expirations++
			logger.Debug("Cache item expired:", key)
		}
	}
}

func (c *LocalCache) GetMetrics() *CacheMetrics {
	return c.metrics
}

func (c *LocalCache) incrementHits()        { c.metrics.hits++ }
func (c *LocalCache) incrementMisses()      { c.metrics.misses++ }
func (c *LocalCache) incrementEvictions()   { c.metrics.evictions++ }
func (c *LocalCache) incrementExpirations() { c.metrics.expirations++ }

// Stop cleanup goroutine
func (c *LocalCache) Stop() {
	c.cleanupTicker.Stop()
}
