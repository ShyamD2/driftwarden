package terraform

import (
	"path/filepath"
	"testing"

	"github.com/ShyamD2/driftwarden/pkg/models"
)

func TestStateParser_SchemaV4(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "testdata", "state_v4.json")
	parser := NewStateParser("us-east-1", "123456789012")

	resources, stateFile, err := parser.ParseFile(fixturePath)
	if err != nil {
		t.Fatalf("failed to parse state_v4.json: %v", err)
	}

	if stateFile.Version != 4 {
		t.Errorf("expected version 4, got %d", stateFile.Version)
	}
	if stateFile.Serial != 42 {
		t.Errorf("expected serial 42, got %d", stateFile.Serial)
	}
	if len(resources) != 5 {
		t.Fatalf("expected 5 state resources, got %d", len(resources))
	}

	resMap := make(map[string]models.CanonicalResource)
	for _, r := range resources {
		resMap[r.Type+"."+r.Name] = r
	}

	// 1. VPC
	vpc := resMap["aws_vpc.main"]
	if vpc.ProviderID != "vpc-0123456789" {
		t.Errorf("expected vpc ProviderID vpc-0123456789, got %q", vpc.ProviderID)
	}
	if vpc.CanonicalID != "aws:aws:ec2:us-east-1:123456789012:vpc/vpc-0123456789" {
		t.Errorf("expected vpc CanonicalID aws:aws:ec2:us-east-1:123456789012:vpc/vpc-0123456789, got %q", vpc.CanonicalID)
	}
	if vpc.Source != models.SourceState {
		t.Errorf("expected SourceState, got %v", vpc.Source)
	}
	if vpc.Availability != models.AvailabilityPresent {
		t.Errorf("expected AvailabilityPresent, got %v", vpc.Availability)
	}
	if vpc.IdentityConfidence != 1.0 {
		t.Errorf("expected identity confidence 1.0, got %f", vpc.IdentityConfidence)
	}

	// 2. Subnet
	subnet := resMap["aws_subnet.public"]
	if subnet.CanonicalID != "aws:aws:ec2:us-east-1:123456789012:subnet/subnet-0123456789" {
		t.Errorf("expected subnet CanonicalID aws:aws:ec2:us-east-1:123456789012:subnet/subnet-0123456789, got %q", subnet.CanonicalID)
	}

	// 3. Security Group
	sg := resMap["aws_security_group.web"]
	if sg.CanonicalID != "aws:aws:ec2:us-east-1:123456789012:security-group/sg-0123456789" {
		t.Errorf("expected sg CanonicalID aws:aws:ec2:us-east-1:123456789012:security-group/sg-0123456789, got %q", sg.CanonicalID)
	}

	// 4. Instance
	inst := resMap["aws_instance.web_server"]
	if inst.CanonicalID != "aws:aws:ec2:us-east-1:123456789012:instance/i-0123456789" {
		t.Errorf("expected instance CanonicalID aws:aws:ec2:us-east-1:123456789012:instance/i-0123456789, got %q", inst.CanonicalID)
	}

	// 5. S3 Bucket (global URN without region/account)
	s3Bucket := resMap["aws_s3_bucket.assets"]
	if s3Bucket.CanonicalID != "aws:aws:s3:::bucket/company-assets-prod-123456" {
		t.Errorf("expected s3 CanonicalID aws:aws:s3:::bucket/company-assets-prod-123456, got %q", s3Bucket.CanonicalID)
	}
}
