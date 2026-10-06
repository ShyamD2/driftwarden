package terraform_semantics

import (
	"testing"

	"github.com/ShyamD2/driftwarden/pkg/diff"
	"github.com/ShyamD2/driftwarden/pkg/identity"
	"github.com/ShyamD2/driftwarden/pkg/models"
	"github.com/ShyamD2/driftwarden/pkg/normalizer"
	"github.com/ShyamD2/driftwarden/pkg/terraform"
)

// 1. Computed & Unknown Values
func TestComputedAndUnknownValues_NoFalseDrift(t *testing.T) {
	comparator := diff.NewComparator(diff.ComparatorOptions{})

	// Desired has attributes marked AttributeUnknown, AttributeExpression, AttributeReference
	desired := []models.CanonicalResource{
		{
			CanonicalID:  "aws:aws:ec2:us-east-1:123456789012:instance/i-computed-01",
			Type:         "aws_instance",
			ProviderID:   "i-computed-01",
			Name:         "web",
			AccountID:    "123456789012",
			Region:       "us-east-1",
			Availability: models.AvailabilityPresent,
			Attributes: map[string]any{
				"instance_type": "t3.micro",
				"ami":           "ami-dynamic",
				"subnet_id":     "subnet-dynamic",
				"user_data":     "computed_blob",
				"_attribute_kinds": map[string]models.AttributeValueKind{
					"ami":       models.AttributeReference,
					"subnet_id": models.AttributeExpression,
					"user_data": models.AttributeUnknown,
				},
			},
		},
	}

	state := []models.CanonicalResource{
		{
			CanonicalID:  "aws:aws:ec2:us-east-1:123456789012:instance/i-computed-01",
			Type:         "aws_instance",
			ProviderID:   "i-computed-01",
			Name:         "web",
			AccountID:    "123456789012",
			Region:       "us-east-1",
			Availability: models.AvailabilityPresent,
			Attributes: map[string]any{
				"instance_type": "t3.micro",
				"ami":           "ami-0123456789abcdef0",
				"subnet_id":     "subnet-0123456789abcdef0",
				"user_data":     "base64encodedscript",
			},
		},
	}

	live := []models.CanonicalResource{
		{
			CanonicalID:  "aws:aws:ec2:us-east-1:123456789012:instance/i-computed-01",
			Type:         "aws_instance",
			ProviderID:   "i-computed-01",
			Name:         "web",
			AccountID:    "123456789012",
			Region:       "us-east-1",
			Availability: models.AvailabilityPresent,
			Attributes: map[string]any{
				"instance_type": "t3.micro",
				"ami":           "ami-0123456789abcdef0",
				"subnet_id":     "subnet-0123456789abcdef0",
				"user_data":     "base64encodedscript",
			},
		},
	}

	// S and L match completely. Desired has unresolved values. Must NOT emit false drift!
	report := comparator.Correlate(desired, state, live, "scan-test-computed", "123456789012", []string{"us-east-1"})

	if len(report.Items) != 0 {
		t.Fatalf("expected 0 drift items (no false drift for unresolved desired attributes), got %d: %+v",
			len(report.Items), report.Items)
	}

	// Now introduce an actual drift between State and Live on a resolved attribute
	live[0].Attributes["instance_type"] = "t3.large"
	reportWithDrift := comparator.Correlate(desired, state, live, "scan-test-computed-2", "123456789012", []string{"us-east-1"})

	if len(reportWithDrift.Items) != 1 {
		t.Fatalf("expected 1 drift item for real instance_type drift, got %d", len(reportWithDrift.Items))
	}

	item := reportWithDrift.Items[0]
	// Verify unresolved attributes are recorded with UNRESOLVED_DESIRED_VALUE in diffs
	for _, attr := range []string{"ami", "subnet_id", "user_data"} {
		diffDetail, exists := item.Diffs[attr]
		if !exists {
			t.Errorf("expected diff detail for unresolved attribute %s", attr)
			continue
		}
		if diffDetail.ResolutionStatus != "UNRESOLVED_DESIRED_VALUE" {
			t.Errorf("expected ResolutionStatus UNRESOLVED_DESIRED_VALUE for %s, got %q",
				attr, diffDetail.ResolutionStatus)
		}
	}

	// Verify HCL parsing automatically identifies expressions and references
	hclCode := `
resource "aws_instance" "web" {
  instance_type = var.env == "prod" ? "m5.large" : "t3.micro"
  ami           = data.aws_ami.ubuntu.id
  tags          = { "Name" = "web-server" }
}
`
	cp := terraform.NewConfigParser("us-east-1", "123456789012")
	_, desList, err := cp.ParseBytes([]byte(hclCode), "main.tf")
	if err != nil {
		t.Fatalf("failed to parse HCL: %v", err)
	}
	if len(desList) != 1 {
		t.Fatalf("expected 1 desired resource parsed from HCL, got %d", len(desList))
	}
	kinds := desList[0].AttributeKinds
	if kinds["instance_type"] != models.AttributeExpression {
		t.Errorf("expected instance_type kind AttributeExpression, got %v", kinds["instance_type"])
	}
	if kinds["ami"] != models.AttributeReference {
		t.Errorf("expected ami kind AttributeReference, got %v", kinds["ami"])
	}
}

// 2. Indexed Resource Names (count & for_each)
func TestIndexedResourceNames_CountAndForEach(t *testing.T) {
	// A. Parse Terraform addresses with index keys
	testCases := []struct {
		address      string
		expectedType string
		expectedName string
		expectedKey  string
	}{
		{
			address:      `aws_instance.web[0]`,
			expectedType: "aws_instance",
			expectedName: "web",
			expectedKey:  "0",
		},
		{
			address:      `aws_instance.web[1]`,
			expectedType: "aws_instance",
			expectedName: "web",
			expectedKey:  "1",
		},
		{
			address:      `aws_s3_bucket.buckets["data"]`,
			expectedType: "aws_s3_bucket",
			expectedName: "buckets",
			expectedKey:  "data",
		},
		{
			address:      `aws_s3_bucket.buckets["logs"]`,
			expectedType: "aws_s3_bucket",
			expectedName: "buckets",
			expectedKey:  "logs",
		},
	}

	for _, tc := range testCases {
		parsed, err := identity.ParseTerraformAddress(tc.address)
		if err != nil {
			t.Fatalf("ParseTerraformAddress(%q) failed: %v", tc.address, err)
		}
		if parsed.Type != tc.expectedType {
			t.Errorf("expected type %q for %s, got %q", tc.expectedType, tc.address, parsed.Type)
		}
		if parsed.Name != tc.expectedName {
			t.Errorf("expected name %q for %s, got %q", tc.expectedName, tc.address, parsed.Name)
		}
		if parsed.Key != tc.expectedKey {
			t.Errorf("expected key %q for %s, got %q", tc.expectedKey, tc.address, parsed.Key)
		}
	}

	// B. Test state parser handling of indexed resources
	stateJSON := `{
  "version": 4,
  "terraform_version": "1.5.0",
  "serial": 1,
  "resources": [
    {
      "mode": "managed",
      "type": "aws_instance",
      "name": "web",
      "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
      "instances": [
        {
          "index_key": 0,
          "attributes": {
            "id": "i-web-0",
            "instance_type": "t3.micro"
          }
        },
        {
          "index_key": 1,
          "attributes": {
            "id": "i-web-1",
            "instance_type": "t3.micro"
          }
        }
      ]
    },
    {
      "mode": "managed",
      "type": "aws_s3_bucket",
      "name": "buckets",
      "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
      "instances": [
        {
          "index_key": "data",
          "attributes": {
            "id": "my-data-bucket-prod",
            "bucket": "my-data-bucket-prod"
          }
        }
      ]
    }
  ]
}`

	sp := terraform.NewStateParser("us-east-1", "123456789012")
	resources, _, err := sp.ParseBytes([]byte(stateJSON), "terraform.tfstate")
	if err != nil {
		t.Fatalf("StateParser failed: %v", err)
	}

	if len(resources) != 3 {
		t.Fatalf("expected 3 canonical resources, got %d", len(resources))
	}

	// Verify addresses in evidence
	foundAddresses := make(map[string]bool)
	for _, res := range resources {
		for _, ev := range res.IdentityEvidence {
			if len(ev) > 19 && ev[:19] == "terraform address: " {
				foundAddresses[ev[19:]] = true
			}
		}
	}

	expectedAddrs := []string{
		"aws_instance.web[0]",
		"aws_instance.web[1]",
		`aws_s3_bucket.buckets["data"]`,
	}
	for _, addr := range expectedAddrs {
		if !foundAddresses[addr] {
			t.Errorf("expected evidence to record terraform address %q, got: %+v", addr, foundAddresses)
		}
	}
}

// 3. Nested Modules Address Format
func TestNestedModules_AddressFormatting(t *testing.T) {
	// A. Parse nested module addresses
	nestedAddresses := []struct {
		address      string
		expectedMod  string
		expectedType string
		expectedName string
		expectedKey  string
	}{
		{
			address:      "module.vpc.module.subnets.aws_subnet.public",
			expectedMod:  "module.vpc.module.subnets",
			expectedType: "aws_subnet",
			expectedName: "public",
			expectedKey:  "",
		},
		{
			address:      "module.vpc.module.subnets.aws_subnet.public[0]",
			expectedMod:  "module.vpc.module.subnets",
			expectedType: "aws_subnet",
			expectedName: "public",
			expectedKey:  "0",
		},
		{
			address:      `module.infra.module.networking.module.subnets.aws_subnet.private["zone-a"]`,
			expectedMod:  "module.infra.module.networking.module.subnets",
			expectedType: "aws_subnet",
			expectedName: "private",
			expectedKey:  "zone-a",
		},
	}

	for _, tc := range nestedAddresses {
		parsed, err := identity.ParseTerraformAddress(tc.address)
		if err != nil {
			t.Fatalf("ParseTerraformAddress(%q) failed: %v", tc.address, err)
		}
		if parsed.Module != tc.expectedMod {
			t.Errorf("expected module %q for %s, got %q", tc.expectedMod, tc.address, parsed.Module)
		}
		if parsed.Type != tc.expectedType {
			t.Errorf("expected type %q for %s, got %q", tc.expectedType, tc.address, parsed.Type)
		}
		if parsed.Name != tc.expectedName {
			t.Errorf("expected name %q for %s, got %q", tc.expectedName, tc.address, parsed.Name)
		}
		if parsed.Key != tc.expectedKey {
			t.Errorf("expected key %q for %s, got %q", tc.expectedKey, tc.address, parsed.Key)
		}
	}

	// B. Verify state parser handles nested module resources
	stateJSON := `{
  "version": 4,
  "terraform_version": "1.5.0",
  "serial": 2,
  "resources": [
    {
      "module": "module.vpc.module.subnets",
      "mode": "managed",
      "type": "aws_subnet",
      "name": "public",
      "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
      "instances": [
        {
          "attributes": {
            "id": "subnet-nested-123",
            "cidr_block": "10.0.1.0/24"
          }
        }
      ]
    }
  ]
}`

	sp := terraform.NewStateParser("us-east-1", "123456789012")
	resources, _, err := sp.ParseBytes([]byte(stateJSON), "terraform.tfstate")
	if err != nil {
		t.Fatalf("StateParser failed on nested module: %v", err)
	}

	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}

	foundNestedAddress := false
	for _, ev := range resources[0].IdentityEvidence {
		if ev == "terraform address: module.vpc.module.subnets.aws_subnet.public" {
			foundNestedAddress = true
			break
		}
	}
	if !foundNestedAddress {
		t.Errorf("expected evidence to contain 'terraform address: module.vpc.module.subnets.aws_subnet.public', got: %+v",
			resources[0].IdentityEvidence)
	}
}

// 4. Data Source Distinction
func TestDataSourceDistinction(t *testing.T) {
	// A. Data sources in HCL must not be treated as managed desired resources
	hclWithData := `
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]
}

data "aws_vpc" "existing" {
  default = true
}

resource "aws_instance" "web" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.micro"
}
`

	cp := terraform.NewConfigParser("us-east-1", "123456789012")
	canonicalList, desiredList, err := cp.ParseBytes([]byte(hclWithData), "main.tf")
	if err != nil {
		t.Fatalf("ParseBytes failed on HCL with data sources: %v", err)
	}

	// Only aws_instance.web should be returned, NOT data.aws_ami.ubuntu or data.aws_vpc.existing
	if len(canonicalList) != 1 {
		t.Fatalf("expected exactly 1 managed desired resource, got %d", len(canonicalList))
	}
	if canonicalList[0].Type != "aws_instance" || canonicalList[0].Name != "web" {
		t.Errorf("expected aws_instance.web, got %s.%s", canonicalList[0].Type, canonicalList[0].Name)
	}
	if len(desiredList) != 1 {
		t.Fatalf("expected exactly 1 desired resource metadata, got %d", len(desiredList))
	}

	// B. Data sources in state file (mode: "data") must be ignored
	stateWithData := `{
  "version": 4,
  "terraform_version": "1.5.0",
  "serial": 3,
  "resources": [
    {
      "mode": "data",
      "type": "aws_ami",
      "name": "ubuntu",
      "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
      "instances": [
        {
          "attributes": {
            "id": "ami-ubuntu-123"
          }
        }
      ]
    },
    {
      "mode": "managed",
      "type": "aws_instance",
      "name": "web",
      "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
      "instances": [
        {
          "attributes": {
            "id": "i-managed-456",
            "ami": "ami-ubuntu-123"
          }
        }
      ]
    }
  ]
}`

	sp := terraform.NewStateParser("us-east-1", "123456789012")
	stateResources, _, err := sp.ParseBytes([]byte(stateWithData), "terraform.tfstate")
	if err != nil {
		t.Fatalf("StateParser failed: %v", err)
	}

	if len(stateResources) != 1 {
		t.Fatalf("expected exactly 1 managed resource from state, got %d", len(stateResources))
	}
	if stateResources[0].Type != "aws_instance" || stateResources[0].ProviderID != "i-managed-456" {
		t.Errorf("expected managed aws_instance i-managed-456, got %s with id %s",
			stateResources[0].Type, stateResources[0].ProviderID)
	}
}

// 5. Implicit Defaults Equivalence
func TestImplicitDefaults_Equivalence(t *testing.T) {
	// A. Unit checks for IsEquivalentToDefault
	if !normalizer.IsEquivalentToDefault("aws_vpc", "enable_dns_hostnames", false) {
		t.Errorf("expected enable_dns_hostnames=false to be equivalent to default")
	}
	if !normalizer.IsEquivalentToDefault("aws_ebs_volume", "encrypted", false) {
		t.Errorf("expected encrypted=false to be equivalent to default")
	}
	if !normalizer.IsEquivalentToDefault("aws_instance", "description", "") {
		t.Errorf("expected empty string to be equivalent to default")
	}
	if !normalizer.IsEquivalentToDefault("aws_security_group", "tags", map[string]any{}) {
		t.Errorf("expected empty map to be equivalent to default")
	}
	if !normalizer.IsEquivalentToDefault("aws_security_group", "ingress", []any{}) {
		t.Errorf("expected empty slice to be equivalent to default")
	}

	// B. 3-Source correlation with omitted defaults: must be IN_SYNC (no false drift)
	comparator := diff.NewComparator(diff.ComparatorOptions{})

	// Desired omits enable_dns_hostnames (nil)
	desired := []models.CanonicalResource{
		{
			CanonicalID:  "aws:aws:ec2:us-east-1:123456789012:vpc/vpc-default-test",
			Type:         "aws_vpc",
			ProviderID:   "vpc-default-test",
			Name:         "main",
			AccountID:    "123456789012",
			Region:       "us-east-1",
			Availability: models.AvailabilityPresent,
			Attributes: map[string]any{
				"cidr_block": "10.0.0.0/16",
				// enable_dns_hostnames omitted
			},
		},
	}

	// State and Live have explicit default false
	state := []models.CanonicalResource{
		{
			CanonicalID:  "aws:aws:ec2:us-east-1:123456789012:vpc/vpc-default-test",
			Type:         "aws_vpc",
			ProviderID:   "vpc-default-test",
			Name:         "main",
			AccountID:    "123456789012",
			Region:       "us-east-1",
			Availability: models.AvailabilityPresent,
			Attributes: map[string]any{
				"cidr_block":           "10.0.0.0/16",
				"enable_dns_hostnames": false,
			},
		},
	}

	live := []models.CanonicalResource{
		{
			CanonicalID:  "aws:aws:ec2:us-east-1:123456789012:vpc/vpc-default-test",
			Type:         "aws_vpc",
			ProviderID:   "vpc-default-test",
			Name:         "main",
			AccountID:    "123456789012",
			Region:       "us-east-1",
			Availability: models.AvailabilityPresent,
			Attributes: map[string]any{
				"cidr_block":           "10.0.0.0/16",
				"enable_dns_hostnames": false,
			},
		},
	}

	report := comparator.Correlate(desired, state, live, "scan-defaults", "123456789012", []string{"us-east-1"})
	if len(report.Items) != 0 {
		t.Fatalf("expected 0 drift items when omitting default boolean attribute, got %d: %+v",
			len(report.Items), report.Items)
	}
}
