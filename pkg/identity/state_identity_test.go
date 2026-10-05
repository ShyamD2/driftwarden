package identity

import (
	"testing"

	"github.com/ShyamD2/driftwarden/pkg/models"
)

func TestExtractStateIdentityPrecedence(t *testing.T) {
	// 1. ARN present -> confidence = 1.0
	attrs1 := map[string]any{
		"arn":  "arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789",
		"id":   "i-0123456789",
		"name": "my-instance",
	}
	res1 := ExtractStateIdentity("aws_instance", attrs1)
	if res1.Confidence != 1.0 {
		t.Errorf("expected confidence 1.0 for ARN, got %f", res1.Confidence)
	}
	if res1.ProviderID != "i-0123456789" {
		t.Errorf("expected providerID i-0123456789, got %q", res1.ProviderID)
	}
	if res1.Availability != models.AvailabilityPresent {
		t.Errorf("expected AvailabilityPresent, got %v", res1.Availability)
	}

	// 2. ARN missing, ID present -> confidence = 1.0
	attrs2 := map[string]any{
		"id":   "sg-9876543210",
		"name": "web-secgroup",
	}
	res2 := ExtractStateIdentity("aws_security_group", attrs2)
	if res2.Confidence != 1.0 {
		t.Errorf("expected confidence 1.0 for ID, got %f", res2.Confidence)
	}
	if res2.ProviderID != "sg-9876543210" {
		t.Errorf("expected providerID sg-9876543210, got %q", res2.ProviderID)
	}

	// 3. ARN missing, ID missing, Name present -> confidence = 0.8
	attrs3 := map[string]any{
		"name": "production-role",
	}
	res3 := ExtractStateIdentity("aws_iam_role", attrs3)
	if res3.Confidence != 0.8 {
		t.Errorf("expected confidence 0.8 for Name fallback, got %f", res3.Confidence)
	}
	if res3.ProviderID != "production-role" {
		t.Errorf("expected providerID production-role, got %q", res3.ProviderID)
	}

	// 4. Missing all -> AvailabilityUnknown, confidence = 0.4
	attrs4 := map[string]any{
		"foo": "bar",
	}
	res4 := ExtractStateIdentity("aws_instance", attrs4)
	if res4.Confidence != 0.4 {
		t.Errorf("expected confidence 0.4 for empty identity, got %f", res4.Confidence)
	}
	if res4.Availability != models.AvailabilityUnknown {
		t.Errorf("expected AvailabilityUnknown, got %v", res4.Availability)
	}
}
