package collector

import (
	"context"
	"math/rand"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"golang.org/x/time/rate"

	dwErrors "github.com/ShyamD2/driftwarden/pkg/errors"
	"github.com/ShyamD2/driftwarden/pkg/models"
)

// Dispatcher coordinates concurrent resource collection bounded by a worker pool and rate limiter.
type Dispatcher struct {
	concurrency int
	limiter     *rate.Limiter
	registry    *Registry
}

// NewDispatcher creates a new Dispatcher.
func NewDispatcher(concurrency int, rateLimit int, registry *Registry) *Dispatcher {
	if concurrency <= 0 {
		concurrency = 8
	}
	if rateLimit <= 0 {
		rateLimit = 15
	}
	if registry == nil {
		registry = DefaultRegistry()
	}

	limit := rate.Limit(rateLimit)
	limiter := rate.NewLimiter(limit, rateLimit)

	return &Dispatcher{
		concurrency: concurrency,
		limiter:     limiter,
		registry:    registry,
	}
}

// DispatchTask represents a single collection unit for a collector in a region.
type DispatchTask struct {
	Collector ResourceCollector
	Region    string
	Config    aws.Config
}

// DispatchResult represents the result of a collection task.
type DispatchResult struct {
	ResourceType string
	Region       string
	Resources    []models.CanonicalResource
	Err          error
}

// Dispatch runs collection across all specified collectors and regions concurrently.
func (d *Dispatcher) Dispatch(ctx context.Context, cfg aws.Config, regions []string, resourceTypes []string) ([]models.CanonicalResource, []error) {
	collectors := make([]ResourceCollector, 0)
	if len(resourceTypes) == 0 {
		collectors = d.registry.All()
	} else {
		for _, rt := range resourceTypes {
			if c, ok := d.registry.Get(rt); ok {
				collectors = append(collectors, c)
			}
		}
	}

	// Build task list
	var tasks []DispatchTask
	for _, reg := range regions {
		for _, c := range collectors {
			tasks = append(tasks, DispatchTask{
				Collector: c,
				Region:    reg,
				Config:    cfg,
			})
		}
	}

	taskChan := make(chan DispatchTask, len(tasks))
	for _, t := range tasks {
		taskChan <- t
	}
	close(taskChan)

	resultChan := make(chan DispatchResult, len(tasks))
	var wg sync.WaitGroup

	workerCount := d.concurrency
	if workerCount > len(tasks) && len(tasks) > 0 {
		workerCount = len(tasks)
	}

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range taskChan {
				select {
				case <-ctx.Done():
					resultChan <- DispatchResult{
						ResourceType: task.Collector.ResourceType(),
						Region:       task.Region,
						Err:          ctx.Err(),
					}
					return
				default:
				}

				// Wait on shared global rate limiter
				if err := d.limiter.Wait(ctx); err != nil {
					resultChan <- DispatchResult{
						ResourceType: task.Collector.ResourceType(),
						Region:       task.Region,
						Err:          err,
					}
					continue
				}

				// Execute collection with retry middleware
				res, err := ExecuteWithRetry(ctx, 3, func() ([]models.CanonicalResource, error) {
					return task.Collector.Collect(ctx, task.Config, task.Region)
				})

				resultChan <- DispatchResult{
					ResourceType: task.Collector.ResourceType(),
					Region:       task.Region,
					Resources:    res,
					Err:          err,
				}
			}
		}()
	}

	wg.Wait()
	close(resultChan)

	var allResources []models.CanonicalResource
	var errs []error

	for r := range resultChan {
		if r.Err != nil {
			errs = append(errs, r.Err)
		} else {
			allResources = append(allResources, r.Resources...)
		}
	}

	return allResources, errs
}

// ExecuteWithRetry executes an action with exponential backoff and decorrelated jitter on retryable errors.
func ExecuteWithRetry[T any](ctx context.Context, maxRetries int, fn func() (T, error)) (T, error) {
	var zero T
	backoff := 250 * time.Millisecond
	maxBackoff := 4 * time.Second

	for attempt := 0; attempt <= maxRetries; attempt++ {
		val, err := fn()
		if err == nil {
			return val, nil
		}

		classified := dwErrors.Classify(err)
		if !classified.IsRetryable() || attempt == maxRetries {
			return zero, classified
		}

		// Decorrelated jitter
		jitter := time.Duration(rand.Int63n(int64(backoff / 2)))
		sleep := backoff + jitter

		select {
		case <-ctx.Done():
			return zero, ctx.Err()
		case <-time.After(sleep):
		}

		backoff = backoff * 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}

	return zero, ctx.Err()
}
