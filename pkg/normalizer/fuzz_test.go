package normalizer

import (
	"reflect"
	"strings"
	"testing"

	"github.com/ShyamD2/driftwarden/pkg/models"
)

// FuzzNormalizerIdempotency tests the invariant that normalizing a resource
// twice produces the exact same canonical representation: N(N(x)) == N(x).
func FuzzNormalizerIdempotency(f *testing.F) {
	norm := NewNormalizer(false)

	// Seed corpus
	f.Add("aws_instance", "i-12345", "tag1", "val1", "aws:cloudformation:stack", "foo", "arn", "arn:aws:ec2:us-east-1:123:instance/i-12345")
	f.Add("aws_security_group", "sg-123", "Name", "default", "aws:tag", "bar", "id", "sg-123")
	f.Add("aws_s3_bucket", "my-bucket", "Owner", "secops", "aws:created-by", "cdk", "creation_date", "2026-01-01")

	f.Fuzz(func(t *testing.T, resType, resID, tagKey1, tagVal1, sysTagKey, sysTagVal, compAttrKey, compAttrVal string) {
		attrs := map[string]any{
			compAttrKey: compAttrVal,
			"valid_key": "valid_val",
		}
		tags := map[string]string{
			tagKey1:   tagVal1,
			sysTagKey: sysTagVal,
		}

		res := &models.CanonicalResource{
			Type:        resType,
			ProviderID:  resID,
			Attributes:  attrs,
			Tags:        tags,
		}

		// First normalization
		norm.Normalize(res)

		// Snapshot state after first normalization
		tagsFirst := make(map[string]string)
		for k, v := range res.Tags {
			tagsFirst[k] = v
		}
		attrsFirst := make(map[string]any)
		for k, v := range res.Attributes {
			attrsFirst[k] = v
		}
		isDefaultFirst := res.IsDefault

		// Second normalization
		norm.Normalize(res)

		// Invariant: Idempotency holds
		if !reflect.DeepEqual(res.Tags, tagsFirst) {
			t.Fatalf("Tag idempotency violated: first=%v, second=%v", tagsFirst, res.Tags)
		}
		if !reflect.DeepEqual(res.Attributes, attrsFirst) {
			t.Fatalf("Attribute idempotency violated: first=%v, second=%v", attrsFirst, res.Attributes)
		}
		if res.IsDefault != isDefaultFirst {
			t.Fatalf("IsDefault idempotency violated: first=%v, second=%v", isDefaultFirst, res.IsDefault)
		}
	})
}

// FuzzSecurityGroupRuleSortingPermutations tests the invariant that reordering
// semantically unordered rules always results in identical canonical sorting.
func FuzzSecurityGroupRuleSortingPermutations(f *testing.F) {
	norm := NewNormalizer(false)

	f.Add("tcp", 22, 22, "0.0.0.0/0", "tcp", 443, 443, "10.0.0.0/8")
	f.Add("udp", 53, 53, "192.168.1.0/24", "tcp", 80, 80, "0.0.0.0/0")

	f.Fuzz(func(t *testing.T, proto1 string, from1, to1 int, cidr1 string, proto2 string, from2, to2 int, cidr2 string) {
		ruleA := map[string]any{
			"protocol":    proto1,
			"from_port":   from1,
			"to_port":     to1,
			"cidr_blocks": []any{cidr1},
		}
		ruleB := map[string]any{
			"protocol":    proto2,
			"from_port":   from2,
			"to_port":     to2,
			"cidr_blocks": []any{cidr2},
		}

		// Setup Order 1: [A, B]
		res1 := &models.CanonicalResource{
			Type: "aws_security_group",
			Attributes: map[string]any{
				"ingress": []any{ruleA, ruleB},
			},
		}
		norm.Normalize(res1)

		// Setup Order 2: [B, A]
		res2 := &models.CanonicalResource{
			Type: "aws_security_group",
			Attributes: map[string]any{
				"ingress": []any{ruleB, ruleA},
			},
		}
		norm.Normalize(res2)

		// Invariant: Both must sort to identical slice of rule keys
		rules1 := res1.Attributes["ingress"].([]any)
		rules2 := res2.Attributes["ingress"].([]any)

		key1_0 := ruleSortKey(rules1[0])
		key1_1 := ruleSortKey(rules1[1])
		key2_0 := ruleSortKey(rules2[0])
		key2_1 := ruleSortKey(rules2[1])

		if key1_0 != key2_0 || key1_1 != key2_1 {
			t.Fatalf("Rule sorting order-independence invariant failed: [%s, %s] != [%s, %s]",
				key1_0, key1_1, key2_0, key2_1)
		}
	})
}

// FuzzSensitiveMasking tests the invariant that secret values never leak
// and are always replaced with [REDACTED].
func FuzzSensitiveMasking(f *testing.F) {
	f.Add("master_password", "SuperSecret123!")
	f.Add("secret_key", "AKIA-SECRET-VALUE-XYZ")
	f.Add("admin_token", "bearer-token-random-hex")
	f.Add("certificate_private_key", "-----BEGIN RSA PRIVATE KEY-----")

	f.Fuzz(func(t *testing.T, keyName, secretVal string) {
		if strings.TrimSpace(secretVal) == "" {
			return
		}

		redacted := RedactSensitiveValue(keyName, secretVal)

		if IsSensitiveAttribute(keyName) {
			// Invariant 1: Redacted value must equal RedactedPlaceholder
			if redacted != RedactedPlaceholder {
				t.Fatalf("Sensitive attribute %s was not redacted: got %v", keyName, redacted)
			}
			// Invariant 2: Original secret value must not appear in redacted output
			if redacted == secretVal {
				t.Fatalf("Sensitive attribute %s leaked original secret: %s", keyName, secretVal)
			}
		}
	})
}
