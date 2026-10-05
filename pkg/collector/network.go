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

func networkCapabilities() models.CollectorCapabilities {
	return models.CollectorCapabilities{
		Discover:        true,
		Normalize:       true,
		Compare:         true,
		SecurityAnalyze: true,
		CostEstimate:    false,
		Reconcile:       true,
	}
}

// ==========================================
// 4. aws_security_group Collector
// ==========================================

type SecurityGroupCollector struct {
	clientFactory func(cfg aws.Config, region string) EC2ClientAPI
}

func NewSecurityGroupCollector() *SecurityGroupCollector {
	return &SecurityGroupCollector{clientFactory: defaultEC2ClientFactory}
}

func (c *SecurityGroupCollector) ResourceType() string {
	return identity.TypeAWSSecurityGroup
}

func (c *SecurityGroupCollector) Capabilities() models.CollectorCapabilities {
	return networkCapabilities()
}

func (c *SecurityGroupCollector) Collect(ctx context.Context, cfg aws.Config, region string) ([]models.CanonicalResource, error) {
	client := c.clientFactory(cfg, region)
	paginator := ec2.NewDescribeSecurityGroupsPaginator(client, &ec2.DescribeSecurityGroupsInput{})

	var results []models.CanonicalResource
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, dwErrors.Classify(err)
		}

		for _, sg := range page.SecurityGroups {
			res := mapSGToCanonical(sg, region)
			results = append(results, res)
		}
	}
	return results, nil
}

func (c *SecurityGroupCollector) Get(ctx context.Context, cfg aws.Config, region string, providerID string) (*models.CanonicalResource, error) {
	client := c.clientFactory(cfg, region)
	out, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		GroupIds: []string{providerID},
	})
	if err != nil {
		return nil, dwErrors.Classify(err)
	}

	for _, sg := range out.SecurityGroups {
		if aws.ToString(sg.GroupId) == providerID {
			mapped := mapSGToCanonical(sg, region)
			return &mapped, nil
		}
	}
	return nil, dwErrors.New(dwErrors.ErrNotFound, fmt.Sprintf("security group %s not found", providerID))
}

func mapSGToCanonical(sg ec2Types.SecurityGroup, region string) models.CanonicalResource {
	sgID := aws.ToString(sg.GroupId)
	accountID := aws.ToString(sg.OwnerId)
	name := aws.ToString(sg.GroupName)
	tags := make(map[string]string)

	for _, t := range sg.Tags {
		tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
	}

	isDefault := name == "default"

	attrs := map[string]any{
		"id":          sgID,
		"name":        name,
		"description": aws.ToString(sg.Description),
		"vpc_id":      aws.ToString(sg.VpcId),
		"is_default":  isDefault,
	}

	canonicalID := identity.CanonicalIDForType(identity.TypeAWSSecurityGroup, region, accountID, sgID)

	return models.CanonicalResource{
		CanonicalID:        canonicalID,
		Type:               identity.TypeAWSSecurityGroup,
		ProviderID:         sgID,
		Name:               name,
		AccountID:          accountID,
		Region:             region,
		Attributes:         attrs,
		Tags:               tags,
		Source:             models.SourceLive,
		Availability:       models.AvailabilityPresent,
		IsDefault:          isDefault,
		IdentityConfidence: 1.0,
		IdentityEvidence: []string{
			fmt.Sprintf("observed via ec2.DescribeSecurityGroups in %s", region),
		},
	}
}

// ==========================================
// 5. aws_vpc Collector
// ==========================================

type VPCCollector struct {
	clientFactory func(cfg aws.Config, region string) EC2ClientAPI
}

func NewVPCCollector() *VPCCollector {
	return &VPCCollector{clientFactory: defaultEC2ClientFactory}
}

func (c *VPCCollector) ResourceType() string {
	return identity.TypeAWSVPC
}

func (c *VPCCollector) Capabilities() models.CollectorCapabilities {
	return networkCapabilities()
}

func (c *VPCCollector) Collect(ctx context.Context, cfg aws.Config, region string) ([]models.CanonicalResource, error) {
	client := c.clientFactory(cfg, region)
	paginator := ec2.NewDescribeVpcsPaginator(client, &ec2.DescribeVpcsInput{})

	var results []models.CanonicalResource
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, dwErrors.Classify(err)
		}

		for _, vpc := range page.Vpcs {
			res := mapVPCToCanonical(vpc, region)
			results = append(results, res)
		}
	}
	return results, nil
}

func (c *VPCCollector) Get(ctx context.Context, cfg aws.Config, region string, providerID string) (*models.CanonicalResource, error) {
	client := c.clientFactory(cfg, region)
	out, err := client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{
		VpcIds: []string{providerID},
	})
	if err != nil {
		return nil, dwErrors.Classify(err)
	}

	for _, vpc := range out.Vpcs {
		if aws.ToString(vpc.VpcId) == providerID {
			mapped := mapVPCToCanonical(vpc, region)
			return &mapped, nil
		}
	}
	return nil, dwErrors.New(dwErrors.ErrNotFound, fmt.Sprintf("vpc %s not found", providerID))
}

func mapVPCToCanonical(vpc ec2Types.Vpc, region string) models.CanonicalResource {
	vpcID := aws.ToString(vpc.VpcId)
	accountID := aws.ToString(vpc.OwnerId)
	isDefault := aws.ToBool(vpc.IsDefault)
	name := vpcID
	tags := make(map[string]string)

	for _, t := range vpc.Tags {
		k := aws.ToString(t.Key)
		v := aws.ToString(t.Value)
		tags[k] = v
		if strings.EqualFold(k, "name") && v != "" {
			name = v
		}
	}

	attrs := map[string]any{
		"id":         vpcID,
		"cidr_block": aws.ToString(vpc.CidrBlock),
		"state":      string(vpc.State),
		"is_default": isDefault,
	}

	canonicalID := identity.CanonicalIDForType(identity.TypeAWSVPC, region, accountID, vpcID)

	return models.CanonicalResource{
		CanonicalID:        canonicalID,
		Type:               identity.TypeAWSVPC,
		ProviderID:         vpcID,
		Name:               name,
		AccountID:          accountID,
		Region:             region,
		Attributes:         attrs,
		Tags:               tags,
		Source:             models.SourceLive,
		Availability:       models.AvailabilityPresent,
		IsDefault:          isDefault,
		IdentityConfidence: 1.0,
		IdentityEvidence: []string{
			fmt.Sprintf("observed via ec2.DescribeVpcs in %s", region),
		},
	}
}

// ==========================================
// 6. aws_subnet Collector
// ==========================================

type SubnetCollector struct {
	clientFactory func(cfg aws.Config, region string) EC2ClientAPI
}

func NewSubnetCollector() *SubnetCollector {
	return &SubnetCollector{clientFactory: defaultEC2ClientFactory}
}

func (c *SubnetCollector) ResourceType() string {
	return identity.TypeAWSSubnet
}

func (c *SubnetCollector) Capabilities() models.CollectorCapabilities {
	return networkCapabilities()
}

func (c *SubnetCollector) Collect(ctx context.Context, cfg aws.Config, region string) ([]models.CanonicalResource, error) {
	client := c.clientFactory(cfg, region)
	paginator := ec2.NewDescribeSubnetsPaginator(client, &ec2.DescribeSubnetsInput{})

	var results []models.CanonicalResource
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, dwErrors.Classify(err)
		}

		for _, sub := range page.Subnets {
			res := mapSubnetToCanonical(sub, region)
			results = append(results, res)
		}
	}
	return results, nil
}

func (c *SubnetCollector) Get(ctx context.Context, cfg aws.Config, region string, providerID string) (*models.CanonicalResource, error) {
	client := c.clientFactory(cfg, region)
	out, err := client.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{
		SubnetIds: []string{providerID},
	})
	if err != nil {
		return nil, dwErrors.Classify(err)
	}

	for _, sub := range out.Subnets {
		if aws.ToString(sub.SubnetId) == providerID {
			mapped := mapSubnetToCanonical(sub, region)
			return &mapped, nil
		}
	}
	return nil, dwErrors.New(dwErrors.ErrNotFound, fmt.Sprintf("subnet %s not found", providerID))
}

func mapSubnetToCanonical(sub ec2Types.Subnet, region string) models.CanonicalResource {
	subnetID := aws.ToString(sub.SubnetId)
	accountID := aws.ToString(sub.OwnerId)
	isDefault := aws.ToBool(sub.DefaultForAz)
	name := subnetID
	tags := make(map[string]string)

	for _, t := range sub.Tags {
		k := aws.ToString(t.Key)
		v := aws.ToString(t.Value)
		tags[k] = v
		if strings.EqualFold(k, "name") && v != "" {
			name = v
		}
	}

	attrs := map[string]any{
		"id":                      subnetID,
		"vpc_id":                  aws.ToString(sub.VpcId),
		"cidr_block":              aws.ToString(sub.CidrBlock),
		"availability_zone":       aws.ToString(sub.AvailabilityZone),
		"default_for_az":          isDefault,
		"map_public_ip_on_launch": aws.ToBool(sub.MapPublicIpOnLaunch),
	}

	canonicalID := identity.CanonicalIDForType(identity.TypeAWSSubnet, region, accountID, subnetID)

	return models.CanonicalResource{
		CanonicalID:        canonicalID,
		Type:               identity.TypeAWSSubnet,
		ProviderID:         subnetID,
		Name:               name,
		AccountID:          accountID,
		Region:             region,
		Attributes:         attrs,
		Tags:               tags,
		Source:             models.SourceLive,
		Availability:       models.AvailabilityPresent,
		IsDefault:          isDefault,
		IdentityConfidence: 1.0,
		IdentityEvidence: []string{
			fmt.Sprintf("observed via ec2.DescribeSubnets in %s", region),
		},
	}
}

// ==========================================
// 7. aws_route_table Collector
// ==========================================

type RouteTableCollector struct {
	clientFactory func(cfg aws.Config, region string) EC2ClientAPI
}

func NewRouteTableCollector() *RouteTableCollector {
	return &RouteTableCollector{clientFactory: defaultEC2ClientFactory}
}

func (c *RouteTableCollector) ResourceType() string {
	return identity.TypeAWSRouteTable
}

func (c *RouteTableCollector) Capabilities() models.CollectorCapabilities {
	return networkCapabilities()
}

func (c *RouteTableCollector) Collect(ctx context.Context, cfg aws.Config, region string) ([]models.CanonicalResource, error) {
	client := c.clientFactory(cfg, region)
	paginator := ec2.NewDescribeRouteTablesPaginator(client, &ec2.DescribeRouteTablesInput{})

	var results []models.CanonicalResource
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, dwErrors.Classify(err)
		}

		for _, rtb := range page.RouteTables {
			res := mapRouteTableToCanonical(rtb, region)
			results = append(results, res)
		}
	}
	return results, nil
}

func (c *RouteTableCollector) Get(ctx context.Context, cfg aws.Config, region string, providerID string) (*models.CanonicalResource, error) {
	client := c.clientFactory(cfg, region)
	out, err := client.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{
		RouteTableIds: []string{providerID},
	})
	if err != nil {
		return nil, dwErrors.Classify(err)
	}

	for _, rtb := range out.RouteTables {
		if aws.ToString(rtb.RouteTableId) == providerID {
			mapped := mapRouteTableToCanonical(rtb, region)
			return &mapped, nil
		}
	}
	return nil, dwErrors.New(dwErrors.ErrNotFound, fmt.Sprintf("route table %s not found", providerID))
}

func mapRouteTableToCanonical(rtb ec2Types.RouteTable, region string) models.CanonicalResource {
	rtbID := aws.ToString(rtb.RouteTableId)
	accountID := aws.ToString(rtb.OwnerId)
	name := rtbID
	tags := make(map[string]string)

	for _, t := range rtb.Tags {
		k := aws.ToString(t.Key)
		v := aws.ToString(t.Value)
		tags[k] = v
		if strings.EqualFold(k, "name") && v != "" {
			name = v
		}
	}

	// Identify main / default association
	isMain := false
	for _, assoc := range rtb.Associations {
		if aws.ToBool(assoc.Main) {
			isMain = true
			break
		}
	}

	attrs := map[string]any{
		"id":      rtbID,
		"vpc_id":  aws.ToString(rtb.VpcId),
		"is_main": isMain,
	}

	canonicalID := identity.CanonicalIDForType(identity.TypeAWSRouteTable, region, accountID, rtbID)

	return models.CanonicalResource{
		CanonicalID:        canonicalID,
		Type:               identity.TypeAWSRouteTable,
		ProviderID:         rtbID,
		Name:               name,
		AccountID:          accountID,
		Region:             region,
		Attributes:         attrs,
		Tags:               tags,
		Source:             models.SourceLive,
		Availability:       models.AvailabilityPresent,
		IsDefault:          isMain,
		IdentityConfidence: 1.0,
		IdentityEvidence: []string{
			fmt.Sprintf("observed via ec2.DescribeRouteTables in %s", region),
		},
	}
}

func init() {
	Register(NewSecurityGroupCollector())
	Register(NewVPCCollector())
	Register(NewSubnetCollector())
	Register(NewRouteTableCollector())
}
