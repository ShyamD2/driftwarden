package normalizer

import (
	"testing"

	"github.com/ShyamD2/driftwarden/pkg/models"
)

func TestNormalizer_TagCleaningAndComputedStripping(t *testing.T) {
	res := &models.CanonicalResource{
		Type: "aws_instance",
		Name: "web",
		Attributes: map[string]any{
			"id":                   "i-0123456789",
			"arn":                  "arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789",
			"owner_id":             "123456789012",
			"creation_date":        "2026-01-01T00:00:00Z",
			"availability_zone_id": "use1-az1",
			"instance_type":        "t3.micro",
		},
		Tags: map[string]string{
			"Environment":                 "Production",
			"aws:cloudformation:stack-id": "stack-123",
			"aws:ec2launch:version":       "2.0",
		},
	}

	norm := NewNormalizer(false)
	norm.Normalize(res)

	// Verify computed metadata stripped
	for _, stripped := range []string{"id", "arn", "owner_id", "creation_date", "availability_zone_id"} {
		if _, exists := res.Attributes[stripped]; exists {
			t.Errorf("expected computed attribute %q to be stripped", stripped)
		}
	}
	if res.Attributes["instance_type"] != "t3.micro" {
		t.Errorf("expected instance_type to be preserved, got %v", res.Attributes["instance_type"])
	}

	// Verify cloud-injected system tags stripped
	if _, exists := res.Tags["aws:cloudformation:stack-id"]; exists {
		t.Errorf("expected aws:cloudformation tag to be stripped")
	}
	if _, exists := res.Tags["aws:ec2launch:version"]; exists {
		t.Errorf("expected aws:ec2launch tag to be stripped")
	}
	if res.Tags["Environment"] != "Production" {
		t.Errorf("expected Environment tag to be preserved")
	}
}

func TestNormalizer_SecurityGroupRuleSorting(t *testing.T) {
	rules := []any{
		map[string]any{"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr_block": "0.0.0.0/0"},
		map[string]any{"protocol": "tcp", "from_port": 80, "to_port": 80, "cidr_block": "0.0.0.0/0"},
		map[string]any{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_block": "10.0.0.0/16"},
	}

	res := &models.CanonicalResource{
		Type: "aws_security_group",
		Attributes: map[string]any{
			"ingress": rules,
		},
	}

	norm := NewNormalizer(false)
	norm.Normalize(res)

	sorted := res.Attributes["ingress"].([]any)
	first := sorted[0].(map[string]any)
	if first["from_port"] != 22 {
		t.Errorf("expected port 22 first after deterministic sorting, got %v", first["from_port"])
	}
}
