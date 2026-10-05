package terraform

import (
	"path/filepath"
	"testing"

	"github.com/ShyamD2/driftwarden/pkg/models"
)

func TestConfigParser_Categorization(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "testdata", "baseline.tf")
	parser := NewConfigParser("us-east-1", "123456789012")

	canonicalList, desiredList, err := parser.ParseFile(fixturePath)
	if err != nil {
		t.Fatalf("failed to parse baseline.tf: %v", err)
	}

	if len(canonicalList) != 5 {
		t.Fatalf("expected 5 canonical resources, got %d", len(canonicalList))
	}

	// Index by resource address: type.name
	desMap := make(map[string]DesiredResource)
	for _, dr := range desiredList {
		key := dr.Resource.Type + "." + dr.Resource.Name
		desMap[key] = dr
	}

	// 1. Verify aws_vpc.main
	vpc, ok := desMap["aws_vpc.main"]
	if !ok {
		t.Fatal("missing aws_vpc.main in parsed resources")
	}
	if vpc.Resource.Source != models.SourceDesired {
		t.Errorf("expected SourceDesired, got %v", vpc.Resource.Source)
	}
	if vpc.Resource.Availability != models.AvailabilityPresent {
		t.Errorf("expected AvailabilityPresent, got %v", vpc.Resource.Availability)
	}
	// Verify AttributeValueKind
	if vpc.AttributeKinds["cidr_block"] != models.AttributeLiteral {
		t.Errorf("expected cidr_block to be AttributeLiteral, got %v", vpc.AttributeKinds["cidr_block"])
	}
	if vpc.AttributeKinds["enable_dns_hostnames"] != models.AttributeLiteral {
		t.Errorf("expected enable_dns_hostnames to be AttributeLiteral, got %v", vpc.AttributeKinds["enable_dns_hostnames"])
	}

	// 2. Verify aws_subnet.public has reference to vpc
	subnet, ok := desMap["aws_subnet.public"]
	if !ok {
		t.Fatal("missing aws_subnet.public")
	}
	if subnet.AttributeKinds["vpc_id"] != models.AttributeReference {
		t.Errorf("expected vpc_id to be AttributeReference, got %v", subnet.AttributeKinds["vpc_id"])
	}

	// 3. Verify aws_instance.web_server lifecycle ignore_changes
	instance, ok := desMap["aws_instance.web_server"]
	if !ok {
		t.Fatal("missing aws_instance.web_server")
	}
	if len(instance.IgnoreChanges) != 2 {
		t.Fatalf("expected 2 ignore_changes, got %d: %v", len(instance.IgnoreChanges), instance.IgnoreChanges)
	}
	hasTags := false
	hasAMI := false
	for _, ic := range instance.IgnoreChanges {
		if ic == "tags" {
			hasTags = true
		}
		if ic == "ami" {
			hasAMI = true
		}
	}
	if !hasTags || !hasAMI {
		t.Errorf("expected ignore_changes to contain 'tags' and 'ami', got %v", instance.IgnoreChanges)
	}
}
