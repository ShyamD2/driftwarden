package identity

import (
	"testing"
)

func TestCanonicalIDDeterminism(t *testing.T) {
	tests := []struct {
		name       string
		components CanonicalComponents
		expected   string
	}{
		{
			name: "EC2 Instance Determinism",
			components: CanonicalComponents{
				Partition:    "aws",
				Service:      "ec2",
				Region:       "us-east-1",
				AccountID:    "123456789012",
				ResourceType: "instance",
				ResourceID:   "i-0123456789",
			},
			expected: "aws:aws:ec2:us-east-1:123456789012:instance/i-0123456789",
		},
		{
			name: "S3 Bucket Global Resource Determinism (empty region and account)",
			components: CanonicalComponents{
				Partition:    "aws",
				Service:      "s3",
				Region:       "",
				AccountID:    "",
				ResourceType: "bucket",
				ResourceID:   "example-bucket",
			},
			expected: "aws:aws:s3:::bucket/example-bucket",
		},
		{
			name: "IAM Role Global Resource Determinism (empty region)",
			components: CanonicalComponents{
				Partition:    "aws",
				Service:      "iam",
				Region:       "",
				AccountID:    "123456789012",
				ResourceType: "role",
				ResourceID:   "MyRole",
			},
			expected: "aws:aws:iam::123456789012:role/MyRole",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate twice to verify byte-for-byte determinism
			res1 := GenerateCanonicalID(tt.components)
			res2 := GenerateCanonicalID(tt.components)

			if res1 != tt.expected {
				t.Fatalf("GenerateCanonicalID() = %q; want %q", res1, tt.expected)
			}
			if res1 != res2 {
				t.Fatalf("Non-deterministic generation: res1=%q != res2=%q", res1, res2)
			}

			// Verify parsing round-trip
			parsed, err := ParseCanonicalID(res1)
			if err != nil {
				t.Fatalf("ParseCanonicalID(%q) error: %v", res1, err)
			}
			rebuilt := GenerateCanonicalID(parsed)
			if rebuilt != tt.expected {
				t.Fatalf("Round-trip mismatch: got %q, want %q", rebuilt, tt.expected)
			}
		})
	}
}

func TestCoreTypesCanonicalID(t *testing.T) {
	coreTests := []struct {
		resType    string
		region     string
		account    string
		providerID string
		expected   string
	}{
		{
			resType:    TypeAWSInstance,
			region:     "us-east-1",
			account:    "123456789012",
			providerID: "i-0123456789",
			expected:   "aws:aws:ec2:us-east-1:123456789012:instance/i-0123456789",
		},
		{
			resType:    TypeAWSEBSVolume,
			region:     "us-east-1",
			account:    "123456789012",
			providerID: "vol-0123456789",
			expected:   "aws:aws:ec2:us-east-1:123456789012:volume/vol-0123456789",
		},
		{
			resType:    TypeAWSEIP,
			region:     "us-east-1",
			account:    "123456789012",
			providerID: "eipalloc-0123456789",
			expected:   "aws:aws:ec2:us-east-1:123456789012:elastic-ip/eipalloc-0123456789",
		},
		{
			resType:    TypeAWSSecurityGroup,
			region:     "us-east-1",
			account:    "123456789012",
			providerID: "sg-0123456789",
			expected:   "aws:aws:ec2:us-east-1:123456789012:security-group/sg-0123456789",
		},
		{
			resType:    TypeAWSVPC,
			region:     "us-east-1",
			account:    "123456789012",
			providerID: "vpc-0123456789",
			expected:   "aws:aws:ec2:us-east-1:123456789012:vpc/vpc-0123456789",
		},
		{
			resType:    TypeAWSSubnet,
			region:     "us-east-1",
			account:    "123456789012",
			providerID: "subnet-0123456789",
			expected:   "aws:aws:ec2:us-east-1:123456789012:subnet/subnet-0123456789",
		},
		{
			resType:    TypeAWSRouteTable,
			region:     "us-east-1",
			account:    "123456789012",
			providerID: "rtb-0123456789",
			expected:   "aws:aws:ec2:us-east-1:123456789012:route-table/rtb-0123456789",
		},
		{
			resType:    TypeAWSS3Bucket,
			region:     "us-east-1", // Should be ignored/omitted for S3 global bucket URN
			account:    "123456789012",
			providerID: "example-bucket",
			expected:   "aws:aws:s3:::bucket/example-bucket",
		},
		{
			resType:    TypeAWSIAMRole,
			region:     "us-east-1", // Should be ignored/omitted for IAM role URN
			account:    "123456789012",
			providerID: "MyRole",
			expected:   "aws:aws:iam::123456789012:role/MyRole",
		},
	}

	for _, tt := range coreTests {
		got := CanonicalIDForType(tt.resType, tt.region, tt.account, tt.providerID)
		if got != tt.expected {
			t.Errorf("CanonicalIDForType(%s) = %q; want %q", tt.resType, got, tt.expected)
		}
	}
}
