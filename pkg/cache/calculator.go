// pkg/cache/calculator.go

package cache

import (
	"otp-service/pkg/logger"
	"runtime"

	"github.com/shirou/gopsutil/v3/mem"
)

type CacheSizeCalculator struct {
	totalMemory      uint64
	maxMemoryPercent float64
	averageItemSize  uint64
}

func NewCacheSizeCalculator() *CacheSizeCalculator {
	return &CacheSizeCalculator{
		maxMemoryPercent: 0.2,  // Use up to 20% of available memory
		averageItemSize:  1024, // Assume average OTP object is ~1KB
	}
}

func (c *CacheSizeCalculator) CalculateMaxSize() (int, error) {
	// Get system memory info
	v, err := mem.VirtualMemory()
	if err != nil {
		return 0, err
	}

	// Get available memory
	availableMemory := v.Available

	// Calculate max memory for cache
	maxCacheMemory := uint64(float64(availableMemory) * c.maxMemoryPercent)

	// Calculate max items
	maxItems := maxCacheMemory / c.averageItemSize

	// Set a reasonable limit
	if maxItems > 1000000 {
		maxItems = 1000000 // Cap at 1 million items
	}

	return int(maxItems), nil
}

// Monitor memory usage
func (c *CacheSizeCalculator) MonitorMemoryUsage() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// Log memory statistics
	logger.Info("Memory stats:",
		"Alloc", byteToMB(m.Alloc),
		"TotalAlloc", byteToMB(m.TotalAlloc),
		"Sys", byteToMB(m.Sys),
		"NumGC", m.NumGC,
	)
}

func byteToMB(b uint64) uint64 {
	return b / 1024 / 1024
}
