package diff

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/ShyamD2/driftwarden/pkg/collector"
	dwErrors "github.com/ShyamD2/driftwarden/pkg/errors"
	"github.com/ShyamD2/driftwarden/pkg/models"
)

type mockProbeCollector struct {
	getFunc func(ctx context.Context, cfg aws.Config, region string, providerID string) (*models.CanonicalResource, error)
}

func (m *mockProbeCollector) ResourceType() string {
	return "aws_instance"
}

func (m *mockProbeCollector) Capabilities() models.CollectorCapabilities {
	return models.CollectorCapabilities{Discover: true}
}

func (m *mockProbeCollector) Collect(ctx context.Context, cfg aws.Config, region string) ([]models.CanonicalResource, error) {
	return nil, nil
}

func (m *mockProbeCollector) Get(ctx context.Context, cfg aws.Config, region string, providerID string) (*models.CanonicalResource, error) {
	return m.getFunc(ctx, cfg, region, providerID)
}

func TestConsistencyProbe_Ghost_ConfirmedNotFound(t *testing.T) {
	mockCol := &mockProbeCollector{
		getFunc: func(ctx context.Context, cfg aws.Config, region string, providerID string) (*models.CanonicalResource, error) {
			return nil, dwErrors.New(dwErrors.ErrNotFound, "instance does not exist")
		},
	}

	reg := collector.NewRegistry()
	reg.Register(mockCol)

	probe := NewConsistencyProbe(0, reg)

	item := &models.DriftItem{
		Type: models.DriftGhost,
		Resource: models.CanonicalResource{
			Type:       "aws_instance",
			ProviderID: "i-ghost123",
			Region:     "us-east-1",
		},
	}

	keepDrift, err := probe.VerifyConsistency(context.Background(), aws.Config{}, item, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !keepDrift {
		t.Errorf("expected keepDrift=true for confirmed ghost")
	}
	if !item.DoubleReadVerified {
		t.Errorf("expected DoubleReadVerified=true on confirmed ErrNotFound")
	}
}

func TestConsistencyProbe_TransientAttributePropagationLag(t *testing.T) {
	// Second read returns attributes matching state (eventual consistency lag resolved)
	mockCol := &mockProbeCollector{
		getFunc: func(ctx context.Context, cfg aws.Config, region string, providerID string) (*models.CanonicalResource, error) {
			return &models.CanonicalResource{
				Type:       "aws_instance",
				ProviderID: "i-inst123",
				Region:     "us-east-1",
				Attributes: map[string]any{
					"instance_type": "t3.large", // Now matches state!
				},
			}, nil
		},
	}

	reg := collector.NewRegistry()
	reg.Register(mockCol)

	probe := NewConsistencyProbe(10*time.Millisecond, reg)

	item := &models.DriftItem{
		Type: models.DriftAttribute,
		Resource: models.CanonicalResource{
			Type:       "aws_instance",
			ProviderID: "i-inst123",
			Region:     "us-east-1",
			Attributes: map[string]any{
				"instance_type": "t3.micro", // Stale live reading
			},
		},
	}

	stateRes := &models.CanonicalResource{
		Type:       "aws_instance",
		ProviderID: "i-inst123",
		Attributes: map[string]any{
			"instance_type": "t3.large",
		},
	}

	keepDrift, err := probe.VerifyConsistency(context.Background(), aws.Config{}, item, stateRes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Transient lag resolved -> discard drift!
	if keepDrift {
		t.Errorf("expected keepDrift=false when second read matches state")
	}
	if !item.DoubleReadVerified {
		t.Errorf("expected DoubleReadVerified=true")
	}
}

func TestConsistencyProbe_AccessDeniedBoundary(t *testing.T) {
	mockCol := &mockProbeCollector{
		getFunc: func(ctx context.Context, cfg aws.Config, region string, providerID string) (*models.CanonicalResource, error) {
			return nil, errors.New("AccessDenied: User unauthorized")
		},
	}

	reg := collector.NewRegistry()
	reg.Register(mockCol)

	probe := NewConsistencyProbe(0, reg)

	item := &models.DriftItem{
		Type: models.DriftGhost,
		Resource: models.CanonicalResource{
			Type:       "aws_instance",
			ProviderID: "i-ghost123",
			Region:     "us-east-1",
		},
	}

	keepDrift, err := probe.VerifyConsistency(context.Background(), aws.Config{}, item, nil)
	if err == nil {
		t.Fatal("expected error on AccessDenied")
	}
	if keepDrift {
		t.Errorf("expected keepDrift=false on AccessDenied")
	}
	classified := dwErrors.Classify(err)
	if classified.Code != dwErrors.ErrAccessDenied {
		t.Errorf("expected ErrAccessDenied, got %v", classified.Code)
	}
}
