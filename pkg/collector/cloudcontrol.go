package collector

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"

	dwErrors "github.com/ShyamD2/driftwarden/pkg/errors"
	"github.com/ShyamD2/driftwarden/pkg/identity"
	"github.com/ShyamD2/driftwarden/pkg/models"
)

// CloudControlAPIClient defines the operations needed for CloudControl collection.
type CloudControlAPIClient interface {
	ListResources(ctx context.Context, params *cloudcontrol.ListResourcesInput, optFns ...func(*cloudcontrol.Options)) (*cloudcontrol.ListResourcesOutput, error)
	GetResource(ctx context.Context, params *cloudcontrol.GetResourceInput, optFns ...func(*cloudcontrol.Options)) (*cloudcontrol.GetResourceOutput, error)
}

var defaultCloudControlClientFactory = func(cfg aws.Config, region string) CloudControlAPIClient {
	return cloudcontrol.NewFromConfig(cfg, func(o *cloudcontrol.Options) {
		if region != "" {
			o.Region = region
		}
	})
}

// CloudControlCollector provides generic CloudFormation/CloudControl asset inventory discovery.
type CloudControlCollector struct {
	TypeName      string // e.g. "AWS::Logs::LogGroup"
	clientFactory func(cfg aws.Config, region string) CloudControlAPIClient
}

func NewCloudControlCollector(typeName string) *CloudControlCollector {
	return &CloudControlCollector{
		TypeName:      typeName,
		clientFactory: defaultCloudControlClientFactory,
	}
}

func (c *CloudControlCollector) ResourceType() string {
	return c.TypeName
}

func (c *CloudControlCollector) Capabilities() models.CollectorCapabilities {
	// Strict Tier 2 contract: discovery-only unmanaged asset inventory
	return models.CollectorCapabilities{
		Discover:        true,
		Normalize:       false,
		Compare:         false,
		SecurityAnalyze: false,
		CostEstimate:    false,
		Reconcile:       false,
	}
}

func (c *CloudControlCollector) Collect(ctx context.Context, cfg aws.Config, region string) ([]models.CanonicalResource, error) {
	client := c.clientFactory(cfg, region)
	paginator := cloudcontrol.NewListResourcesPaginator(client, &cloudcontrol.ListResourcesInput{
		TypeName: aws.String(c.TypeName),
	})

	var results []models.CanonicalResource
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, dwErrors.Classify(err)
		}

		for _, desc := range page.ResourceDescriptions {
			id := aws.ToString(desc.Identifier)
			canRes := models.CanonicalResource{
				CanonicalID: identity.GenerateCanonicalID(identity.CanonicalComponents{
					Partition:    "aws",
					Service:      "cloudcontrol",
					Region:       region,
					ResourceType: c.TypeName,
					ResourceID:   id,
				}),
				Type:               c.TypeName,
				ProviderID:         id,
				Name:               id,
				Region:             region,
				Attributes:         map[string]any{"identifier": id},
				Source:             models.SourceLive,
				Availability:       models.AvailabilityPresent,
				IdentityConfidence: 1.0,
				IdentityEvidence: []string{
					fmt.Sprintf("observed via cloudcontrol.ListResources for %s in %s", c.TypeName, region),
				},
			}
			results = append(results, canRes)
		}
	}
	return results, nil
}

func (c *CloudControlCollector) Get(ctx context.Context, cfg aws.Config, region string, providerID string) (*models.CanonicalResource, error) {
	client := c.clientFactory(cfg, region)
	out, err := client.GetResource(ctx, &cloudcontrol.GetResourceInput{
		TypeName:   aws.String(c.TypeName),
		Identifier: aws.String(providerID),
	})
	if err != nil {
		return nil, dwErrors.Classify(err)
	}

	if out.ResourceDescription == nil {
		return nil, dwErrors.New(dwErrors.ErrNotFound, fmt.Sprintf("cloudcontrol resource %s/%s not found", c.TypeName, providerID))
	}

	id := aws.ToString(out.ResourceDescription.Identifier)
	canRes := models.CanonicalResource{
		CanonicalID: identity.GenerateCanonicalID(identity.CanonicalComponents{
			Partition:    "aws",
			Service:      "cloudcontrol",
			Region:       region,
			ResourceType: c.TypeName,
			ResourceID:   id,
		}),
		Type:               c.TypeName,
		ProviderID:         id,
		Name:               id,
		Region:             region,
		Attributes:         map[string]any{"identifier": id},
		Source:             models.SourceLive,
		Availability:       models.AvailabilityPresent,
		IdentityConfidence: 1.0,
		IdentityEvidence: []string{
			fmt.Sprintf("observed via cloudcontrol.GetResource for %s in %s", c.TypeName, region),
		},
	}
	return &canRes, nil
}
