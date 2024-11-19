// pkg/cache/ttl_analyzer.go

package cache

import (
	"sync"
	"time"
)

type TTLAnalyzer struct {
	ttlStats map[int]int // Map of TTL values to frequency
	mu       sync.RWMutex
	samples  int
}

func NewTTLAnalyzer() *TTLAnalyzer {
	return &TTLAnalyzer{
		ttlStats: make(map[int]int),
	}
}

func (a *TTLAnalyzer) RecordTTL(ttl int) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.ttlStats[ttl]++
	a.samples++
}

func (a *TTLAnalyzer) CalculateOptimalCleanupInterval() time.Duration {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.samples == 0 {
		return 5 * time.Minute // Default interval
	}

	// Calculate weighted average of TTLs
	var totalWeight int
	var weightedSum int
	for ttl, count := range a.ttlStats {
		weightedSum += ttl * count
		totalWeight += count
	}

	avgTTL := float64(weightedSum) / float64(totalWeight)

	// Set cleanup interval to 1/4 of average TTL
	cleanupInterval := time.Duration(avgTTL/4) * time.Second

	// Ensure reasonable bounds
	switch {
	case cleanupInterval < time.Minute:
		return time.Minute
	case cleanupInterval > 15*time.Minute:
		return 15 * time.Minute
	default:
		return cleanupInterval
	}
}
