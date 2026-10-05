package collector

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2Types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	dwErrors "github.com/ShyamD2/driftwarden/pkg/errors"
	"github.com/ShyamD2/driftwarden/pkg/identity"
	"github.com/ShyamD2/driftwarden/pkg/models"
)

// EC2ClientAPI defines the EC2 operations needed for EC2 and Network collectors.
type EC2ClientAPI interface {
	DescribeInstances(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	DescribeVolumes(ctx context.Context, params *ec2.DescribeVolumesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error)
	DescribeAddresses(ctx context.Context, params *ec2.DescribeAddressesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error)
	DescribeSecurityGroups(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	DescribeVpcs(ctx context.Context, params *ec2.DescribeVpcsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error)
	DescribeSubnets(ctx context.Context, params *ec2.DescribeSubnetsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error)
	DescribeRouteTables(ctx context.Context, params *ec2.DescribeRouteTablesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeRouteTablesOutput, error)
}

// Client factory function hook for testing.
var defaultEC2ClientFactory = func(cfg aws.Config, region string) EC2ClientAPI {
	return ec2.NewFromConfig(cfg, func(o *ec2.Options) {
		if region != "" {
			o.Region = region
		}
	})
}

// ==========================================
// 1. aws_instance Collector
// ==========================================

type EC2InstanceCollector struct {
	clientFactory func(cfg aws.Config, region string) EC2ClientAPI
}

func NewEC2InstanceCollector() *EC2InstanceCollector {
	return &EC2InstanceCollector{clientFactory: defaultEC2ClientFactory}
}

func (c *EC2InstanceCollector) ResourceType() string {
	return identity.TypeAWSInstance
}

func (c *EC2InstanceCollector) Capabilities() models.CollectorCapabilities {
	return models.CollectorCapabilities{
		Discover:        true,
		Normalize:       true,
		Compare:         true,
		SecurityAnalyze: true,
		CostEstimate:    true,
		Reconcile:       true,
	}
}

func (c *EC2InstanceCollector) Collect(ctx context.Context, cfg aws.Config, region string) ([]models.CanonicalResource, error) {
	client := c.clientFactory(cfg, region)
	paginator := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{})

	var results []models.CanonicalResource
	accountID := "" // Will be parsed or populated by dispatcher

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, dwErrors.Classify(err)
		}

		for _, reservation := range page.Reservations {
			if accountID == "" && reservation.OwnerId != nil {
				accountID = *reservation.OwnerId
			}
			for _, inst := range reservation.Instances {
				// Filter out terminated instances
				if inst.State != nil && inst.State.Name == ec2Types.InstanceStateNameTerminated {
					continue
				}
				res := mapEC2InstanceToCanonical(inst, region, accountID)
				results = append(results, res)
			}
		}
	}

	return results, nil
}

func (c *EC2InstanceCollector) Get(ctx context.Context, cfg aws.Config, region string, providerID string) (*models.CanonicalResource, error) {
	client := c.clientFactory(cfg, region)
	out, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: []string{providerID},
	})
	if err != nil {
		return nil, dwErrors.Classify(err)
	}

	for _, res := range out.Reservations {
		for _, inst := range res.Instances {
			if aws.ToString(inst.InstanceId) == providerID {
				if inst.State != nil && inst.State.Name == ec2Types.InstanceStateNameTerminated {
					return nil, dwErrors.New(dwErrors.ErrNotFound, fmt.Sprintf("instance %s is terminated", providerID))
				}
				accountID := aws.ToString(res.OwnerId)
				mapped := mapEC2InstanceToCanonical(inst, region, accountID)
				return &mapped, nil
			}
		}
	}

	return nil, dwErrors.New(dwErrors.ErrNotFound, fmt.Sprintf("instance %s not found", providerID))
}

func mapEC2InstanceToCanonical(inst ec2Types.Instance, region, accountID string) models.CanonicalResource {
	instID := aws.ToString(inst.InstanceId)
	tags := make(map[string]string)
	name := instID

	for _, t := range inst.Tags {
		k := aws.ToString(t.Key)
		v := aws.ToString(t.Value)
		tags[k] = v
		if strings.EqualFold(k, "name") && v != "" {
			name = v
		}
	}

	attrs := map[string]any{
		"id":            instID,
		"instance_type": string(inst.InstanceType),
		"image_id":      aws.ToString(inst.ImageId),
		"subnet_id":     aws.ToString(inst.SubnetId),
		"vpc_id":        aws.ToString(inst.VpcId),
	}
	if inst.State != nil {
		attrs["state"] = string(inst.State.Name)
	}

	canonicalID := identity.CanonicalIDForType(identity.TypeAWSInstance, region, accountID, instID)

	return models.CanonicalResource{
		CanonicalID:        canonicalID,
		Type:               identity.TypeAWSInstance,
		ProviderID:         instID,
		Name:               name,
		AccountID:          accountID,
		Region:             region,
		Attributes:         attrs,
		Tags:               tags,
		Source:             models.SourceLive,
		Availability:       models.AvailabilityPresent,
		IdentityConfidence: 1.0,
		IdentityEvidence: []string{
			fmt.Sprintf("observed via ec2.DescribeInstances in %s", region),
		},
	}
}

// ==========================================
// 2. aws_ebs_volume Collector
// ==========================================

type EBSVolumeCollector struct {
	clientFactory func(cfg aws.Config, region string) EC2ClientAPI
}

func NewEBSVolumeCollector() *EBSVolumeCollector {
	return &EBSVolumeCollector{clientFactory: defaultEC2ClientFactory}
}

func (c *EBSVolumeCollector) ResourceType() string {
	return identity.TypeAWSEBSVolume
}

func (c *EBSVolumeCollector) Capabilities() models.CollectorCapabilities {
	return models.CollectorCapabilities{
		Discover:        true,
		Normalize:       true,
		Compare:         true,
		SecurityAnalyze: true,
		CostEstimate:    true,
		Reconcile:       true,
	}
}

func (c *EBSVolumeCollector) Collect(ctx context.Context, cfg aws.Config, region string) ([]models.CanonicalResource, error) {
	client := c.clientFactory(cfg, region)
	paginator := ec2.NewDescribeVolumesPaginator(client, &ec2.DescribeVolumesInput{})

	var results []models.CanonicalResource
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, dwErrors.Classify(err)
		}

		for _, vol := range page.Volumes {
			res := mapEBSVolumeToCanonical(vol, region, "")
			results = append(results, res)
		}
	}
	return results, nil
}

func (c *EBSVolumeCollector) Get(ctx context.Context, cfg aws.Config, region string, providerID string) (*models.CanonicalResource, error) {
	client := c.clientFactory(cfg, region)
	out, err := client.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{
		VolumeIds: []string{providerID},
	})
	if err != nil {
		return nil, dwErrors.Classify(err)
	}

	for _, vol := range out.Volumes {
		if aws.ToString(vol.VolumeId) == providerID {
			mapped := mapEBSVolumeToCanonical(vol, region, "")
			return &mapped, nil
		}
	}
	return nil, dwErrors.New(dwErrors.ErrNotFound, fmt.Sprintf("volume %s not found", providerID))
}

func mapEBSVolumeToCanonical(vol ec2Types.Volume, region, accountID string) models.CanonicalResource {
	volID := aws.ToString(vol.VolumeId)
	tags := make(map[string]string)
	name := volID

	for _, t := range vol.Tags {
		k := aws.ToString(t.Key)
		v := aws.ToString(t.Value)
		tags[k] = v
		if strings.EqualFold(k, "name") && v != "" {
			name = v
		}
	}

	attrs := map[string]any{
		"id":                volID,
		"size":              aws.ToInt32(vol.Size),
		"volume_type":       string(vol.VolumeType),
		"state":             string(vol.State),
		"encrypted":         aws.ToBool(vol.Encrypted),
		"availability_zone": aws.ToString(vol.AvailabilityZone),
		"unattached":        vol.State == ec2Types.VolumeStateAvailable, // Flag unattached volume
	}

	canonicalID := identity.CanonicalIDForType(identity.TypeAWSEBSVolume, region, accountID, volID)

	return models.CanonicalResource{
		CanonicalID:        canonicalID,
		Type:               identity.TypeAWSEBSVolume,
		ProviderID:         volID,
		Name:               name,
		AccountID:          accountID,
		Region:             region,
		Attributes:         attrs,
		Tags:               tags,
		Source:             models.SourceLive,
		Availability:       models.AvailabilityPresent,
		IdentityConfidence: 1.0,
		IdentityEvidence: []string{
			fmt.Sprintf("observed via ec2.DescribeVolumes in %s", region),
		},
	}
}

// ==========================================
// 3. aws_eip Collector
// ==========================================

type EIPCollector struct {
	clientFactory func(cfg aws.Config, region string) EC2ClientAPI
}

func NewEIPCollector() *EIPCollector {
	return &EIPCollector{clientFactory: defaultEC2ClientFactory}
}

func (c *EIPCollector) ResourceType() string {
	return identity.TypeAWSEIP
}

func (c *EIPCollector) Capabilities() models.CollectorCapabilities {
	return models.CollectorCapabilities{
		Discover:        true,
		Normalize:       true,
		Compare:         true,
		SecurityAnalyze: true,
		CostEstimate:    true,
		Reconcile:       true,
	}
}

// Collect describes addresses. Note: ec2.DescribeAddresses is inherently non-paginated in AWS SDK v2.
func (c *EIPCollector) Collect(ctx context.Context, cfg aws.Config, region string) ([]models.CanonicalResource, error) {
	client := c.clientFactory(cfg, region)
	out, err := client.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{})
	if err != nil {
		return nil, dwErrors.Classify(err)
	}

	var results []models.CanonicalResource
	for _, addr := range out.Addresses {
		res := mapEIPToCanonical(addr, region, "")
		results = append(results, res)
	}
	return results, nil
}

func (c *EIPCollector) Get(ctx context.Context, cfg aws.Config, region string, providerID string) (*models.CanonicalResource, error) {
	client := c.clientFactory(cfg, region)
	out, err := client.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{
		AllocationIds: []string{providerID},
	})
	if err != nil {
		return nil, dwErrors.Classify(err)
	}

	for _, addr := range out.Addresses {
		if aws.ToString(addr.AllocationId) == providerID {
			mapped := mapEIPToCanonical(addr, region, "")
			return &mapped, nil
		}
	}
	return nil, dwErrors.New(dwErrors.ErrNotFound, fmt.Sprintf("eip allocation %s not found", providerID))
}

func mapEIPToCanonical(addr ec2Types.Address, region, accountID string) models.CanonicalResource {
	allocID := aws.ToString(addr.AllocationId)
	if allocID == "" {
		allocID = aws.ToString(addr.PublicIp)
	}

	tags := make(map[string]string)
	name := allocID
	for _, t := range addr.Tags {
		k := aws.ToString(t.Key)
		v := aws.ToString(t.Value)
		tags[k] = v
		if strings.EqualFold(k, "name") && v != "" {
			name = v
		}
	}

	// Flag allocated but unassociated
	unassociated := addr.AssociationId == nil || *addr.AssociationId == ""

	attrs := map[string]any{
		"allocation_id": allocID,
		"public_ip":     aws.ToString(addr.PublicIp),
		"domain":        string(addr.Domain),
		"unassociated":  unassociated,
	}
	if addr.AssociationId != nil {
		attrs["association_id"] = *addr.AssociationId
	}
	if addr.InstanceId != nil {
		attrs["instance_id"] = *addr.InstanceId
	}

	canonicalID := identity.CanonicalIDForType(identity.TypeAWSEIP, region, accountID, allocID)

	return models.CanonicalResource{
		CanonicalID:        canonicalID,
		Type:               identity.TypeAWSEIP,
		ProviderID:         allocID,
		Name:               name,
		AccountID:          accountID,
		Region:             region,
		Attributes:         attrs,
		Tags:               tags,
		Source:             models.SourceLive,
		Availability:       models.AvailabilityPresent,
		IdentityConfidence: 1.0,
		IdentityEvidence: []string{
			fmt.Sprintf("observed via ec2.DescribeAddresses in %s", region),
		},
	}
}

func init() {
	Register(NewEC2InstanceCollector())
	Register(NewEBSVolumeCollector())
	Register(NewEIPCollector())
}
