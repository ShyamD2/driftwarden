package collector

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2Types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	s3Types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	dwErrors "github.com/ShyamD2/driftwarden/pkg/errors"
	"github.com/ShyamD2/driftwarden/pkg/identity"
	"github.com/ShyamD2/driftwarden/tests/mocks"
)

func TestCore9CollectorsImplementCollectAndGet(t *testing.T) {
	// Verify all 9 core types exist in the central registry
	coreTypes := identity.CoreTypes()
	for _, ct := range coreTypes {
		c, ok := DefaultRegistry().Get(ct)
		if !ok {
			t.Fatalf("collector for core type %q is not registered", ct)
		}
		if c.ResourceType() != ct {
			t.Errorf("ResourceType() = %q; want %q", c.ResourceType(), ct)
		}
	}
}

func TestEC2PaginationAndAccessDenied(t *testing.T) {
	mock := &mocks.MockEC2Client{
		InstancePages: [][]*ec2Types.Reservation{
			{
				{
					OwnerId: aws.String("123456789012"),
					Instances: []ec2Types.Instance{
						{
							InstanceId:   aws.String("i-page1-001"),
							InstanceType: ec2Types.InstanceTypeT3Micro,
							State:        &ec2Types.InstanceState{Name: ec2Types.InstanceStateNameRunning},
						},
					},
				},
			},
			{
				{
					OwnerId: aws.String("123456789012"),
					Instances: []ec2Types.Instance{
						{
							InstanceId:   aws.String("i-page2-002"),
							InstanceType: ec2Types.InstanceTypeT3Small,
							State:        &ec2Types.InstanceState{Name: ec2Types.InstanceStateNameRunning},
						},
						{
							// Terminated instance: must be filtered out!
							InstanceId:   aws.String("i-terminated-999"),
							InstanceType: ec2Types.InstanceTypeT3Micro,
							State:        &ec2Types.InstanceState{Name: ec2Types.InstanceStateNameTerminated},
						},
					},
				},
			},
		},
	}

	collector := &EC2InstanceCollector{
		clientFactory: func(cfg aws.Config, region string) EC2ClientAPI {
			return mock
		},
	}

	// 1. Verify multi-page consumption & terminated filter
	resList, err := collector.Collect(context.Background(), aws.Config{}, "us-east-1")
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if len(resList) != 2 {
		t.Fatalf("expected 2 active instances consumed across pages, got %d", len(resList))
	}
	if resList[0].ProviderID != "i-page1-001" || resList[1].ProviderID != "i-page2-002" {
		t.Errorf("unexpected instance IDs collected: %v, %v", resList[0].ProviderID, resList[1].ProviderID)
	}

	// 2. Verify Get
	getRes, err := collector.Get(context.Background(), aws.Config{}, "us-east-1", "i-page1-001")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if getRes.ProviderID != "i-page1-001" {
		t.Errorf("expected ProviderID i-page1-001, got %s", getRes.ProviderID)
	}

	// 3. Verify Permission Handling: AccessDenied returns ErrAccessDenied (never empty slice or ErrNotFound)
	mock.SimulateAccessDenied = true
	deniedList, err := collector.Collect(context.Background(), aws.Config{}, "us-east-1")
	if err == nil {
		t.Fatal("expected error on simulated AccessDenied, got nil")
	}
	if deniedList != nil {
		t.Errorf("expected nil slice on AccessDenied, got %v", deniedList)
	}

	classified := dwErrors.Classify(err)
	if classified.Code != dwErrors.ErrAccessDenied {
		t.Fatalf("CRITICAL INVARIANT VIOLATION: expected ErrAccessDenied, got %v", classified.Code)
	}
	if classified.Code == dwErrors.ErrNotFound {
		t.Fatalf("CRITICAL INVARIANT VIOLATION: AccessDenied was converted to ErrNotFound")
	}
}

func TestIAMPaginationAndServiceLinkedRoleFiltering(t *testing.T) {
	mock := &mocks.MockIAMClient{
		RolePages: [][]*iamTypes.Role{
			{
				{
					RoleName: aws.String("DevOpsAdmin"),
					Arn:      aws.String("arn:aws:iam::123456789012:role/DevOpsAdmin"),
					Path:     aws.String("/"),
				},
				{
					// Service-linked role: must be filtered out!
					RoleName: aws.String("AWSServiceRoleForECS"),
					Arn:      aws.String("arn:aws:iam::123456789012:role/aws-service-role/ecs.amazonaws.com/AWSServiceRoleForECS"),
					Path:     aws.String("/aws-service-role/ecs.amazonaws.com/"),
				},
			},
			{
				{
					RoleName: aws.String("SecurityAuditor"),
					Arn:      aws.String("arn:aws:iam::123456789012:role/SecurityAuditor"),
					Path:     aws.String("/"),
				},
			},
		},
	}

	collector := &IAMRoleCollector{
		clientFactory: func(cfg aws.Config) IAMClientAPI {
			return mock
		},
	}

	// 1. Verify multi-page consumption and service-linked role filtering
	roles, err := collector.Collect(context.Background(), aws.Config{}, "")
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if len(roles) != 2 {
		t.Fatalf("expected 2 roles (excluding service-linked role), got %d", len(roles))
	}
	if roles[0].ProviderID != "DevOpsAdmin" || roles[1].ProviderID != "SecurityAuditor" {
		t.Errorf("unexpected roles collected: %v, %v", roles[0].ProviderID, roles[1].ProviderID)
	}

	// 2. Verify AccessDenied handling
	mock.SimulateAccessDenied = true
	_, err = collector.Collect(context.Background(), aws.Config{}, "")
	if err == nil {
		t.Fatal("expected error on simulated AccessDenied, got nil")
	}
	classified := dwErrors.Classify(err)
	if classified.Code != dwErrors.ErrAccessDenied {
		t.Fatalf("expected ErrAccessDenied, got %v", classified.Code)
	}
}

func TestS3CollectorAccessDenied(t *testing.T) {
	mock := &mocks.MockS3CollectorClient{
		Buckets: []s3Types.Bucket{
			{Name: aws.String("test-bucket-alpha")},
		},
	}

	collector := &S3BucketCollector{
		clientFactory: func(cfg aws.Config, region string) S3BucketClientAPI {
			return mock
		},
	}

	res, err := collector.Collect(context.Background(), aws.Config{}, "us-east-1")
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	if len(res) != 1 || res[0].ProviderID != "test-bucket-alpha" {
		t.Errorf("unexpected buckets: %v", res)
	}

	// Simulated AccessDenied
	mock.SimulateAccessDenied = true
	_, err = collector.Collect(context.Background(), aws.Config{}, "us-east-1")
	if err == nil {
		t.Fatal("expected error on AccessDenied")
	}
	classified := dwErrors.Classify(err)
	if classified.Code != dwErrors.ErrAccessDenied {
		t.Fatalf("expected ErrAccessDenied, got %v", classified.Code)
	}
}
