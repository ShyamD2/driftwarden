package mocks

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	cloudcontrolTypes "github.com/aws/aws-sdk-go-v2/service/cloudcontrol/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2Types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgTypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3Types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	stsTypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
)

// MockEC2Client provides simulated responses and pagination for EC2/VPC collectors.
type MockEC2Client struct {
	SimulateAccessDenied bool
	InstancePages        [][]*ec2Types.Reservation
	VolumePages          [][]*ec2Types.Volume
	Addresses            []ec2Types.Address
	SecurityGroupPages   [][]*ec2Types.SecurityGroup
	VpcPages             [][]*ec2Types.Vpc
	SubnetPages          [][]*ec2Types.Subnet
	RouteTablePages      [][]*ec2Types.RouteTable

	instancePageIndex      int
	volumePageIndex        int
	securityGroupPageIndex int
	vpcPageIndex           int
	subnetPageIndex        int
	routeTablePageIndex    int
}

func (m *MockEC2Client) DescribeInstances(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	if m.SimulateAccessDenied {
		return nil, fmt.Errorf("api error UnauthorizedOperation: You are not authorized to perform this operation")
	}

	if len(params.InstanceIds) > 0 {
		var matched []ec2Types.Reservation
		for _, page := range m.InstancePages {
			for _, res := range page {
				var instances []ec2Types.Instance
				for _, inst := range res.Instances {
					if aws.ToString(inst.InstanceId) == params.InstanceIds[0] {
						instances = append(instances, inst)
					}
				}
				if len(instances) > 0 {
					matched = append(matched, ec2Types.Reservation{
						OwnerId:   res.OwnerId,
						Instances: instances,
					})
				}
			}
		}
		return &ec2.DescribeInstancesOutput{Reservations: matched}, nil
	}

	if m.instancePageIndex >= len(m.InstancePages) {
		return &ec2.DescribeInstancesOutput{}, nil
	}

	page := m.InstancePages[m.instancePageIndex]
	m.instancePageIndex++

	var nextToken *string
	if m.instancePageIndex < len(m.InstancePages) {
		nextToken = aws.String(fmt.Sprintf("page-%d", m.instancePageIndex))
	}

	var reservations []ec2Types.Reservation
	for _, r := range page {
		reservations = append(reservations, *r)
	}

	return &ec2.DescribeInstancesOutput{
		Reservations: reservations,
		NextToken:    nextToken,
	}, nil
}

func (m *MockEC2Client) DescribeVolumes(ctx context.Context, params *ec2.DescribeVolumesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
	if m.SimulateAccessDenied {
		return nil, fmt.Errorf("api error AccessDenied: Access Denied")
	}

	if len(params.VolumeIds) > 0 {
		var matched []ec2Types.Volume
		for _, page := range m.VolumePages {
			for _, vol := range page {
				if aws.ToString(vol.VolumeId) == params.VolumeIds[0] {
					matched = append(matched, *vol)
				}
			}
		}
		return &ec2.DescribeVolumesOutput{Volumes: matched}, nil
	}

	if m.volumePageIndex >= len(m.VolumePages) {
		return &ec2.DescribeVolumesOutput{}, nil
	}

	page := m.VolumePages[m.volumePageIndex]
	m.volumePageIndex++

	var nextToken *string
	if m.volumePageIndex < len(m.VolumePages) {
		nextToken = aws.String(fmt.Sprintf("page-%d", m.volumePageIndex))
	}

	var volumes []ec2Types.Volume
	for _, v := range page {
		volumes = append(volumes, *v)
	}

	return &ec2.DescribeVolumesOutput{
		Volumes:   volumes,
		NextToken: nextToken,
	}, nil
}

func (m *MockEC2Client) DescribeAddresses(ctx context.Context, params *ec2.DescribeAddressesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
	if m.SimulateAccessDenied {
		return nil, fmt.Errorf("api error AccessDenied: Access Denied")
	}

	if len(params.AllocationIds) > 0 {
		var matched []ec2Types.Address
		for _, a := range m.Addresses {
			if aws.ToString(a.AllocationId) == params.AllocationIds[0] {
				matched = append(matched, a)
			}
		}
		return &ec2.DescribeAddressesOutput{Addresses: matched}, nil
	}

	return &ec2.DescribeAddressesOutput{Addresses: m.Addresses}, nil
}

func (m *MockEC2Client) DescribeSecurityGroups(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	if m.SimulateAccessDenied {
		return nil, fmt.Errorf("api error AccessDenied: Access Denied")
	}

	if len(params.GroupIds) > 0 {
		var matched []ec2Types.SecurityGroup
		for _, page := range m.SecurityGroupPages {
			for _, sg := range page {
				if aws.ToString(sg.GroupId) == params.GroupIds[0] {
					matched = append(matched, *sg)
				}
			}
		}
		return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: matched}, nil
	}

	if m.securityGroupPageIndex >= len(m.SecurityGroupPages) {
		return &ec2.DescribeSecurityGroupsOutput{}, nil
	}

	page := m.SecurityGroupPages[m.securityGroupPageIndex]
	m.securityGroupPageIndex++

	var nextToken *string
	if m.securityGroupPageIndex < len(m.SecurityGroupPages) {
		nextToken = aws.String(fmt.Sprintf("page-%d", m.securityGroupPageIndex))
	}

	var sgs []ec2Types.SecurityGroup
	for _, s := range page {
		sgs = append(sgs, *s)
	}

	return &ec2.DescribeSecurityGroupsOutput{
		SecurityGroups: sgs,
		NextToken:      nextToken,
	}, nil
}

func (m *MockEC2Client) DescribeVpcs(ctx context.Context, params *ec2.DescribeVpcsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error) {
	if m.SimulateAccessDenied {
		return nil, fmt.Errorf("api error AccessDenied: Access Denied")
	}

	if len(params.VpcIds) > 0 {
		var matched []ec2Types.Vpc
		for _, page := range m.VpcPages {
			for _, vpc := range page {
				if aws.ToString(vpc.VpcId) == params.VpcIds[0] {
					matched = append(matched, *vpc)
				}
			}
		}
		return &ec2.DescribeVpcsOutput{Vpcs: matched}, nil
	}

	if m.vpcPageIndex >= len(m.VpcPages) {
		return &ec2.DescribeVpcsOutput{}, nil
	}

	page := m.VpcPages[m.vpcPageIndex]
	m.vpcPageIndex++

	var nextToken *string
	if m.vpcPageIndex < len(m.VpcPages) {
		nextToken = aws.String(fmt.Sprintf("page-%d", m.vpcPageIndex))
	}

	var vpcs []ec2Types.Vpc
	for _, v := range page {
		vpcs = append(vpcs, *v)
	}

	return &ec2.DescribeVpcsOutput{
		Vpcs:      vpcs,
		NextToken: nextToken,
	}, nil
}

func (m *MockEC2Client) DescribeSubnets(ctx context.Context, params *ec2.DescribeSubnetsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error) {
	if m.SimulateAccessDenied {
		return nil, fmt.Errorf("api error AccessDenied: Access Denied")
	}

	if len(params.SubnetIds) > 0 {
		var matched []ec2Types.Subnet
		for _, page := range m.SubnetPages {
			for _, sub := range page {
				if aws.ToString(sub.SubnetId) == params.SubnetIds[0] {
					matched = append(matched, *sub)
				}
			}
		}
		return &ec2.DescribeSubnetsOutput{Subnets: matched}, nil
	}

	if m.subnetPageIndex >= len(m.SubnetPages) {
		return &ec2.DescribeSubnetsOutput{}, nil
	}

	page := m.SubnetPages[m.subnetPageIndex]
	m.subnetPageIndex++

	var nextToken *string
	if m.subnetPageIndex < len(m.SubnetPages) {
		nextToken = aws.String(fmt.Sprintf("page-%d", m.subnetPageIndex))
	}

	var subs []ec2Types.Subnet
	for _, s := range page {
		subs = append(subs, *s)
	}

	return &ec2.DescribeSubnetsOutput{
		Subnets:   subs,
		NextToken: nextToken,
	}, nil
}

func (m *MockEC2Client) DescribeRouteTables(ctx context.Context, params *ec2.DescribeRouteTablesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeRouteTablesOutput, error) {
	if m.SimulateAccessDenied {
		return nil, fmt.Errorf("api error AccessDenied: Access Denied")
	}

	if len(params.RouteTableIds) > 0 {
		var matched []ec2Types.RouteTable
		for _, page := range m.RouteTablePages {
			for _, rtb := range page {
				if aws.ToString(rtb.RouteTableId) == params.RouteTableIds[0] {
					matched = append(matched, *rtb)
				}
			}
		}
		return &ec2.DescribeRouteTablesOutput{RouteTables: matched}, nil
	}

	if m.routeTablePageIndex >= len(m.RouteTablePages) {
		return &ec2.DescribeRouteTablesOutput{}, nil
	}

	page := m.RouteTablePages[m.routeTablePageIndex]
	m.routeTablePageIndex++

	var nextToken *string
	if m.routeTablePageIndex < len(m.RouteTablePages) {
		nextToken = aws.String(fmt.Sprintf("page-%d", m.routeTablePageIndex))
	}

	var rtbs []ec2Types.RouteTable
	for _, r := range page {
		rtbs = append(rtbs, *r)
	}

	return &ec2.DescribeRouteTablesOutput{
		RouteTables: rtbs,
		NextToken:   nextToken,
	}, nil
}

// MockS3CollectorClient mocks S3 calls for bucket discovery.
type MockS3CollectorClient struct {
	SimulateAccessDenied bool
	Buckets              []s3Types.Bucket
	PublicAccessBlocks   map[string]*s3Types.PublicAccessBlockConfiguration
}

func (m *MockS3CollectorClient) ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	if m.SimulateAccessDenied {
		return nil, fmt.Errorf("api error AccessDenied: Access Denied")
	}
	return &s3.ListBucketsOutput{Buckets: m.Buckets}, nil
}

func (m *MockS3CollectorClient) GetPublicAccessBlock(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	b := aws.ToString(params.Bucket)
	if p, ok := m.PublicAccessBlocks[b]; ok {
		return &s3.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: p}, nil
	}
	return &s3.GetPublicAccessBlockOutput{}, nil
}

func (m *MockS3CollectorClient) GetBucketEncryption(ctx context.Context, params *s3.GetBucketEncryptionInput, optFns ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error) {
	return &s3.GetBucketEncryptionOutput{}, nil
}

func (m *MockS3CollectorClient) GetBucketTagging(ctx context.Context, params *s3.GetBucketTaggingInput, optFns ...func(*s3.Options)) (*s3.GetBucketTaggingOutput, error) {
	return &s3.GetBucketTaggingOutput{}, nil
}

// MockIAMClient mocks IAM calls with pagination.
type MockIAMClient struct {
	SimulateAccessDenied bool
	RolePages            [][]*iamTypes.Role
	rolePageIndex        int
}

func (m *MockIAMClient) ListRoles(ctx context.Context, params *iam.ListRolesInput, optFns ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	if m.SimulateAccessDenied {
		return nil, fmt.Errorf("api error AccessDenied: Access Denied")
	}

	if m.rolePageIndex >= len(m.RolePages) {
		return &iam.ListRolesOutput{}, nil
	}

	page := m.RolePages[m.rolePageIndex]
	m.rolePageIndex++

	var marker *string
	isTruncated := false
	if m.rolePageIndex < len(m.RolePages) {
		marker = aws.String("marker-next")
		isTruncated = true
	}

	var roles []iamTypes.Role
	for _, r := range page {
		roles = append(roles, *r)
	}

	return &iam.ListRolesOutput{
		Roles:       roles,
		Marker:      marker,
		IsTruncated: isTruncated,
	}, nil
}

func (m *MockIAMClient) GetRole(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
	if m.SimulateAccessDenied {
		return nil, fmt.Errorf("api error AccessDenied: Access Denied")
	}

	for _, page := range m.RolePages {
		for _, r := range page {
			if aws.ToString(r.RoleName) == aws.ToString(params.RoleName) {
				return &iam.GetRoleOutput{Role: r}, nil
			}
		}
	}
	return nil, fmt.Errorf("NoSuchEntity: Role not found")
}

// MockCloudControlClient mocks CloudControl operations.
type MockCloudControlClient struct {
	SimulateAccessDenied bool
	Resources            []cloudcontrolTypes.ResourceDescription
}

func (m *MockCloudControlClient) ListResources(ctx context.Context, params *cloudcontrol.ListResourcesInput, optFns ...func(*cloudcontrol.Options)) (*cloudcontrol.ListResourcesOutput, error) {
	if m.SimulateAccessDenied {
		return nil, fmt.Errorf("api error AccessDenied: Access Denied")
	}
	return &cloudcontrol.ListResourcesOutput{
		ResourceDescriptions: m.Resources,
	}, nil
}

func (m *MockCloudControlClient) GetResource(ctx context.Context, params *cloudcontrol.GetResourceInput, optFns ...func(*cloudcontrol.Options)) (*cloudcontrol.GetResourceOutput, error) {
	if m.SimulateAccessDenied {
		return nil, fmt.Errorf("api error AccessDenied: Access Denied")
	}
	for _, r := range m.Resources {
		if aws.ToString(r.Identifier) == aws.ToString(params.Identifier) {
			return &cloudcontrol.GetResourceOutput{
				ResourceDescription: &r,
			}, nil
		}
	}
	return nil, fmt.Errorf("ResourceNotFoundException")
}

// MockOrganizationsClient mocks Organizations account discovery.
type MockOrganizationsClient struct {
	SimulateAccessDenied bool
	Accounts             []orgTypes.Account
}

func (m *MockOrganizationsClient) ListAccounts(ctx context.Context, params *organizations.ListAccountsInput, optFns ...func(*organizations.Options)) (*organizations.ListAccountsOutput, error) {
	if m.SimulateAccessDenied {
		return nil, fmt.Errorf("api error AccessDenied: Access Denied")
	}
	return &organizations.ListAccountsOutput{
		Accounts: m.Accounts,
	}, nil
}

// MockSTSClient mocks AssumeRole.
type MockSTSClient struct {
	SimulateAccessDenied bool
}

func (m *MockSTSClient) AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	if m.SimulateAccessDenied {
		return nil, fmt.Errorf("api error AccessDenied: Access Denied to assume role")
	}
	return &sts.AssumeRoleOutput{
		AssumedRoleUser: &stsTypes.AssumedRoleUser{
			Arn: aws.String("arn:aws:sts::123456789012:assumed-role/DriftWardenExecutionRole/session"),
		},
	}, nil
}
