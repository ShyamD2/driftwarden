package collector

import (
	"context"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/ShyamD2/driftwarden/pkg/models"
)

// ResourceCollector represents an AWS resource discovery and detail collector.
type ResourceCollector interface {
	ResourceType() string
	Capabilities() models.CollectorCapabilities
	Collect(ctx context.Context, cfg aws.Config, region string) ([]models.CanonicalResource, error)
	Get(ctx context.Context, cfg aws.Config, region string, providerID string) (*models.CanonicalResource, error)
}

// Registry is a thread-safe central repository of resource collectors.
type Registry struct {
	mu         sync.RWMutex
	collectors map[string]ResourceCollector
}

// Global Registry instance.
var (
	defaultRegistry = NewRegistry()
)

// NewRegistry creates a new thread-safe Registry.
func NewRegistry() *Registry {
	return &Registry{
		collectors: make(map[string]ResourceCollector),
	}
}

// DefaultRegistry returns the singleton global registry.
func DefaultRegistry() *Registry {
	return defaultRegistry
}

// Register registers a collector. Panics if collector is nil or ResourceType is empty.
func (r *Registry) Register(c ResourceCollector) {
	if c == nil {
		panic("cannot register nil collector")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.collectors[c.ResourceType()] = c
}

// Get returns the collector registered for the given resource type.
func (r *Registry) Get(resType string) (ResourceCollector, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.collectors[resType]
	return c, ok
}

// All returns a slice of all registered collectors.
func (r *Registry) All() []ResourceCollector {
	r.mu.RLock()
	defer r.mu.RUnlock()
	res := make([]ResourceCollector, 0, len(r.collectors))
	for _, c := range r.collectors {
		res = append(res, c)
	}
	return res
}

// SupportedTypes returns the list of all supported resource type strings.
func (r *Registry) SupportedTypes() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	types := make([]string, 0, len(r.collectors))
	for t := range r.collectors {
		types = append(types, t)
	}
	return types
}

// Register registers a collector to the default global registry.
func Register(c ResourceCollector) {
	defaultRegistry.Register(c)
}

// GetCollector retrieves a collector from the default global registry.
func GetCollector(resType string) (ResourceCollector, error) {
	c, ok := defaultRegistry.Get(resType)
	if !ok {
		return nil, fmt.Errorf("unsupported resource collector: %s", resType)
	}
	return c, nil
}
