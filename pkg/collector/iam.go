package collector

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	dwErrors "github.com/ShyamD2/driftwarden/pkg/errors"
	"github.com/ShyamD2/driftwarden/pkg/identity"
	"github.com/ShyamD2/driftwarden/pkg/models"
)

// IAMClientAPI defines the operations needed for IAM Role collection.
type IAMClientAPI interface {
	ListRoles(ctx context.Context, params *iam.ListRolesInput, optFns ...func(*iam.Options)) (*iam.ListRolesOutput, error)
	GetRole(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error)
}

var defaultIAMClientFactory = func(cfg aws.Config) IAMClientAPI {
	return iam.NewFromConfig(cfg)
}

// IAMRoleCollector collects IAM roles.
type IAMRoleCollector struct {
	clientFactory func(cfg aws.Config) IAMClientAPI
}

func NewIAMRoleCollector() *IAMRoleCollector {
	return &IAMRoleCollector{clientFactory: defaultIAMClientFactory}
}

func (c *IAMRoleCollector) ResourceType() string {
	return identity.TypeAWSIAMRole
}

func (c *IAMRoleCollector) Capabilities() models.CollectorCapabilities {
	return models.CollectorCapabilities{
		Discover:        true,
		Normalize:       true,
		Compare:         true,
		SecurityAnalyze: true,
		CostEstimate:    false,
		Reconcile:       true,
	}
}

func (c *IAMRoleCollector) Collect(ctx context.Context, cfg aws.Config, region string) ([]models.CanonicalResource, error) {
	client := c.clientFactory(cfg)
	paginator := iam.NewListRolesPaginator(client, &iam.ListRolesInput{})

	var results []models.CanonicalResource
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, dwErrors.Classify(err)
		}

		for _, role := range page.Roles {
			// Filter out AWS service-linked roles
			path := aws.ToString(role.Path)
			arn := aws.ToString(role.Arn)
			if strings.Contains(path, "aws-service-role") || strings.Contains(arn, "aws-service-role") {
				continue
			}

			res := mapIAMRoleToCanonical(role)
			results = append(results, res)
		}
	}
	return results, nil
}

func (c *IAMRoleCollector) Get(ctx context.Context, cfg aws.Config, region string, providerID string) (*models.CanonicalResource, error) {
	client := c.clientFactory(cfg)
	out, err := client.GetRole(ctx, &iam.GetRoleInput{
		RoleName: aws.String(providerID),
	})
	if err != nil {
		return nil, dwErrors.Classify(err)
	}

	if out.Role == nil {
		return nil, dwErrors.New(dwErrors.ErrNotFound, fmt.Sprintf("iam role %s not found", providerID))
	}

	role := *out.Role
	path := aws.ToString(role.Path)
	arn := aws.ToString(role.Arn)
	if strings.Contains(path, "aws-service-role") || strings.Contains(arn, "aws-service-role") {
		return nil, dwErrors.New(dwErrors.ErrNotFound, fmt.Sprintf("iam role %s is an ignored service-linked role", providerID))
	}

	mapped := mapIAMRoleToCanonical(role)
	return &mapped, nil
}

func mapIAMRoleToCanonical(role iamTypes.Role) models.CanonicalResource {
	roleName := aws.ToString(role.RoleName)
	arn := aws.ToString(role.Arn)
	accountID := ""

	// Extract account from ARN: arn:aws:iam::<account>:role/...
	arnParts := strings.Split(arn, ":")
	if len(arnParts) >= 5 {
		accountID = arnParts[4]
	}

	tags := make(map[string]string)
	for _, t := range role.Tags {
		tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
	}

	attrs := map[string]any{
		"name":                   roleName,
		"id":                     roleName,
		"arn":                    arn,
		"path":                   aws.ToString(role.Path),
		"assume_role_policy_doc": aws.ToString(role.AssumeRolePolicyDocument),
		"max_session_duration":   aws.ToInt32(role.MaxSessionDuration),
	}

	canonicalID := identity.CanonicalIDForType(identity.TypeAWSIAMRole, "", accountID, roleName)

	return models.CanonicalResource{
		CanonicalID:        canonicalID,
		Type:               identity.TypeAWSIAMRole,
		ProviderID:         roleName,
		Name:               roleName,
		AccountID:          accountID,
		Region:             "",
		Attributes:         attrs,
		Tags:               tags,
		Source:             models.SourceLive,
		Availability:       models.AvailabilityPresent,
		IdentityConfidence: 1.0,
		IdentityEvidence: []string{
			"observed via iam.ListRoles (filtered service-linked roles)",
		},
	}
}

func init() {
	Register(NewIAMRoleCollector())
}
