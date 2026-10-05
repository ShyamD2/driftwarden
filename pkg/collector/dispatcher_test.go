package collector

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	orgTypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"github.com/ShyamD2/driftwarden/pkg/models"
	"github.com/ShyamD2/driftwarden/tests/mocks"
)

type dummyTestCollector struct {
	resType string
}

func (d *dummyTestCollector) ResourceType() string {
	return d.resType
}

func (d *dummyTestCollector) Capabilities() models.CollectorCapabilities {
	return models.CollectorCapabilities{Discover: true}
}

func (d *dummyTestCollector) Collect(ctx context.Context, cfg aws.Config, region string) ([]models.CanonicalResource, error) {
	return []models.CanonicalResource{
		{
			Type:       d.resType,
			ProviderID: "dummy-" + region,
			Region:     region,
		},
	}, nil
}

func (d *dummyTestCollector) Get(ctx context.Context, cfg aws.Config, region string, providerID string) (*models.CanonicalResource, error) {
	return &models.CanonicalResource{
		Type:       d.resType,
		ProviderID: providerID,
		Region:     region,
	}, nil
}

func TestDispatcher_ConcurrencyAndLimiting(t *testing.T) {
	reg := NewRegistry()
	reg.Register(&dummyTestCollector{resType: "test_resource_1"})
	reg.Register(&dummyTestCollector{resType: "test_resource_2"})

	dispatcher := NewDispatcher(4, 50, reg)
	regions := []string{"us-east-1", "us-west-2"}

	resources, errs := dispatcher.Dispatch(context.Background(), aws.Config{}, regions, nil)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors during dispatch: %v", errs)
	}

	// 2 collectors * 2 regions = 4 resources
	if len(resources) != 4 {
		t.Fatalf("expected 4 collected resources, got %d", len(resources))
	}
}

func TestExecuteWithRetry_RetriesOnThrottling(t *testing.T) {
	var attempts int32

	res, err := ExecuteWithRetry(context.Background(), 3, func() (string, error) {
		current := atomic.AddInt32(&attempts, 1)
		if current < 3 {
			// Throttling error is retryable
			return "", errors.New("ThrottlingException: Rate exceeded")
		}
		return "success", nil
	})

	if err != nil {
		t.Fatalf("expected retry to succeed, got: %v", err)
	}
	if res != "success" {
		t.Errorf("expected 'success', got %q", res)
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestOrgDispatcher_MultiAccountFanOut(t *testing.T) {
	reg := NewRegistry()
	reg.Register(&dummyTestCollector{resType: "test_resource"})

	baseDispatcher := NewDispatcher(2, 50, reg)

	mockOrg := &mocks.MockOrganizationsClient{
		Accounts: []orgTypes.Account{
			{
				Id:     aws.String("111111111111"),
				Name:   aws.String("Production-Account"),
				Status: orgTypes.AccountStatusActive,
			},
			{
				Id:     aws.String("222222222222"),
				Name:   aws.String("Staging-Account"),
				Status: orgTypes.AccountStatusActive,
			},
			{
				Id:     aws.String("333333333333"),
				Name:   aws.String("Suspended-Account"),
				Status: orgTypes.AccountStatusSuspended, // Should be skipped!
			},
		},
	}

	mockSTS := &mocks.MockSTSClient{}

	orgDispatcher := NewOrgDispatcher(baseDispatcher, mockOrg, mockSTS, "DriftWardenExecutionRole")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resources, errs := orgDispatcher.DispatchOrg(ctx, aws.Config{}, []string{"us-east-1"}, nil)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}

	// 2 active accounts * 1 collector * 1 region = 2 resources
	if len(resources) != 2 {
		t.Fatalf("expected 2 resources from active accounts, got %d", len(resources))
	}

	// Verify AccountIDs were attached
	accountIDs := make(map[string]bool)
	for _, r := range resources {
		accountIDs[r.AccountID] = true
	}

	if !accountIDs["111111111111"] || !accountIDs["222222222222"] {
		t.Errorf("missing accounts in collected resources: %v", accountIDs)
	}
	if accountIDs["333333333333"] {
		t.Errorf("suspended account 333333333333 should not have been audited")
	}
}
