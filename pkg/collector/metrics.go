package collector

import (
	"sync"
	"sync/atomic"

	"github.com/ShyamD2/driftwarden/pkg/models"
)

// MetricsTracker tracks AWS API queries, retries, and throttles across concurrent collector workers.
type MetricsTracker struct {
	mu             sync.Mutex
	totalCalls     int64
	retries        int64
	throttles      int64
	callsPerRegion map[string]int64
	callsPerType   map[string]int64
}

// NewMetricsTracker initializes an empty tracker.
func NewMetricsTracker() *MetricsTracker {
	return &MetricsTracker{
		callsPerRegion: make(map[string]int64),
		callsPerType:   make(map[string]int64),
	}
}

// RecordCall tracks an API invocation for a region and resource type.
func (m *MetricsTracker) RecordCall(region, resourceType string) {
	if m == nil {
		return
	}
	atomic.AddInt64(&m.totalCalls, 1)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callsPerRegion[region]++
	m.callsPerType[resourceType]++
}

// RecordThrottle increments the throttling event counter.
func (m *MetricsTracker) RecordThrottle() {
	if m == nil {
		return
	}
	atomic.AddInt64(&m.throttles, 1)
}

// RecordRetry increments the retry event counter.
func (m *MetricsTracker) RecordRetry() {
	if m == nil {
		return
	}
	atomic.AddInt64(&m.retries, 1)
}

// Snapshot calculates the efficiency summary.
func (m *MetricsTracker) Snapshot(scannedCount int) *models.APIEfficiency {
	if m == nil {
		return &models.APIEfficiency{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	callsPerRes := 0.0
	if scannedCount > 0 {
		callsPerRes = float64(m.totalCalls) / float64(scannedCount)
	}

	regCopy := make(map[string]int64, len(m.callsPerRegion))
	for k, v := range m.callsPerRegion {
		regCopy[k] = v
	}
	typeCopy := make(map[string]int64, len(m.callsPerType))
	for k, v := range m.callsPerType {
		typeCopy[k] = v
	}

	return &models.APIEfficiency{
		TotalAPICalls:    m.totalCalls,
		Retries:          m.retries,
		Throttles:        m.throttles,
		CallsPerRegion:   regCopy,
		CallsPerService:  typeCopy,
		CallsPerResource: callsPerRes,
	}
}
