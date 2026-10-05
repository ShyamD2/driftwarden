package diff

import (
	"context"
	"reflect"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/ShyamD2/driftwarden/pkg/collector"
	dwErrors "github.com/ShyamD2/driftwarden/pkg/errors"
	"github.com/ShyamD2/driftwarden/pkg/models"
	"github.com/ShyamD2/driftwarden/pkg/normalizer"
)

// ConsistencyProbe executes a double-read verification probe on potential drift items
// to eliminate false positives caused by AWS eventual consistency and control-plane propagation lag.
type ConsistencyProbe struct {
	Delay    time.Duration
	Registry *collector.Registry
}

// NewConsistencyProbe creates a new ConsistencyProbe.
func NewConsistencyProbe(delay time.Duration, registry *collector.Registry) *ConsistencyProbe {
	if registry == nil {
		registry = collector.DefaultRegistry()
	}
	return &ConsistencyProbe{
		Delay:    delay,
		Registry: registry,
	}
}

// VerifyConsistency probes the live AWS API for the resource a second time after the configured delay.
// Returns keepDrift = false if the drift was transient and has resolved in sync with state.
func (cp *ConsistencyProbe) VerifyConsistency(
	ctx context.Context,
	cfg aws.Config,
	item *models.DriftItem,
	stateRes *models.CanonicalResource,
) (keepDrift bool, err error) {
	if item == nil {
		return false, nil
	}

	// 1. Pause for consistency delay if configured
	if cp.Delay > 0 {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-time.After(cp.Delay):
		}
	}

	// 2. Lookup collector for this resource type
	col, ok := cp.Registry.Get(item.Resource.Type)
	if !ok {
		// If no collector registered, cannot double-read probe
		return true, nil
	}

	providerID := item.Resource.ProviderID
	region := item.Resource.Region

	// 3. Execute second read
	secondRead, getErr := col.Get(ctx, cfg, region, providerID)

	switch item.Type {
	case models.DriftGhost:
		if getErr != nil {
			classified := dwErrors.Classify(getErr)
			if classified.Code == dwErrors.ErrNotFound {
				// Confirmed gone: DoubleReadVerified = true
				item.DoubleReadVerified = true
				item.FindingEvidence = append(item.FindingEvidence, "double-read confirmed resource absent (ErrNotFound)")
				return true, nil
			}
			if classified.Code == dwErrors.ErrAccessDenied {
				item.DoubleReadVerified = false
				return false, classified
			}
			return true, getErr
		}

		// Second read succeeded and found the resource: it was not deleted
		item.DoubleReadVerified = true
		item.FindingEvidence = append(item.FindingEvidence, "double-read detected resource still present; ghost drift discarded")
		return false, nil

	case models.DriftAttribute, models.DriftSplitBrain:
		if getErr != nil {
			// Read error during probe
			return true, nil
		}

		if secondRead != nil && stateRes != nil {
			// Check if second read now matches state
			matchesState := true
			norm := normalizer.NewNormalizer(true)
			norm.Normalize(secondRead)

			for k, vState := range stateRes.Attributes {
				if normalizer.ComputedAttributesToStrip[k] {
					continue
				}
				vLive := secondRead.Attributes[k]
				if normalizer.IsSensitiveAttribute(k) {
					if !normalizer.CompareSensitiveAttributes(vState, vLive) {
						matchesState = false
						break
					}
					continue
				}
				if !reflect.DeepEqual(vState, vLive) && !normalizer.IsEquivalentToDefault(item.Resource.Type, k, vLive) {
					matchesState = false
					break
				}
			}

			if matchesState {
				// Matches state now: transient propagation lag
				item.DoubleReadVerified = true
				item.FindingEvidence = append(item.FindingEvidence, "double-read matched state; transient propagation lag resolved")
				return false, nil
			}
		}

		// Still drifted after second read: confirmed drift
		item.DoubleReadVerified = true
		item.FindingEvidence = append(item.FindingEvidence, "double-read verified persistent drift")
		return true, nil

	default:
		// For Shadow resources etc.
		if secondRead != nil && getErr == nil {
			item.DoubleReadVerified = true
		}
		return true, nil
	}
}
