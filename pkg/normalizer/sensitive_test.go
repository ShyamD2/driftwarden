package normalizer

import (
	"testing"
)

func TestSensitiveAttributesMaskingAndComparison(t *testing.T) {
	// 1. Identification
	if !IsSensitiveAttribute("master_password") {
		t.Errorf("expected master_password to be recognized as sensitive")
	}
	if !IsSensitiveAttribute("private_key") {
		t.Errorf("expected private_key to be recognized as sensitive")
	}
	if IsSensitiveAttribute("instance_type") {
		t.Errorf("instance_type should not be recognized as sensitive")
	}

	// 2. Comparison: When state has secret, but AWS returns empty-string/null (write-only), NOT drift!
	if !CompareSensitiveAttributes("super-secret-pass-123", "") {
		t.Errorf("expected sensitive attribute to match when live returns empty string")
	}
	if !CompareSensitiveAttributes("super-secret-pass-123", nil) {
		t.Errorf("expected sensitive attribute to match when live returns nil")
	}

	// 3. Redaction
	redacted := RedactSensitiveValue("db_password", "my-plaintext-secret")
	if redacted != RedactedPlaceholder {
		t.Errorf("expected %s, got %v", RedactedPlaceholder, redacted)
	}
}

func TestIgnoreEngine(t *testing.T) {
	rules := []IgnoreRule{
		{
			Resource:   "aws_instance.*",
			Attributes: []string{"tags", "ami"},
		},
		{
			Resource:   "aws_security_group.web",
			Attributes: []string{"description"},
		},
	}

	engine := NewIgnoreEngine(rules)

	// Instance tags ignored via rule
	if !engine.ShouldIgnore("aws_instance", "server1", "tags", nil) {
		t.Errorf("expected aws_instance.* tags to be ignored")
	}
	if !engine.ShouldIgnore("aws_instance", "server1", "ami", nil) {
		t.Errorf("expected aws_instance.* ami to be ignored")
	}
	if engine.ShouldIgnore("aws_instance", "server1", "instance_type", nil) {
		t.Errorf("instance_type should not be ignored")
	}

	// Lifecycle ignore changes merged
	declaredLifecycle := []string{"volume_size"}
	if !engine.ShouldIgnore("aws_ebs_volume", "vol1", "volume_size", declaredLifecycle) {
		t.Errorf("expected lifecycle.ignore_changes attribute to be ignored")
	}
}
