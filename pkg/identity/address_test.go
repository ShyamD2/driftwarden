package identity

import (
	"testing"
)

func TestParseTerraformAddress(t *testing.T) {
	tests := []struct {
		address      string
		expectedType string
		expectedName string
		expectedKey  string
		expectedMod  string
	}{
		{
			address:      `aws_security_group.web["prod"]`,
			expectedType: "aws_security_group",
			expectedName: "web",
			expectedKey:  "prod",
			expectedMod:  "",
		},
		{
			address:      `aws_instance.server`,
			expectedType: "aws_instance",
			expectedName: "server",
			expectedKey:  "",
			expectedMod:  "",
		},
		{
			address:      `aws_subnet.public[0]`,
			expectedType: "aws_subnet",
			expectedName: "public",
			expectedKey:  "0",
			expectedMod:  "",
		},
		{
			address:      `module.vpc.aws_subnet.public["a"]`,
			expectedType: "aws_subnet",
			expectedName: "public",
			expectedKey:  "a",
			expectedMod:  "module.vpc",
		},
		{
			address:      `module.vpc.module.subnets.aws_subnet.public`,
			expectedType: "aws_subnet",
			expectedName: "public",
			expectedKey:  "",
			expectedMod:  "module.vpc.module.subnets",
		},
		{
			address:      `module.vpc.module.subnets.aws_subnet.public[0]`,
			expectedType: "aws_subnet",
			expectedName: "public",
			expectedKey:  "0",
			expectedMod:  "module.vpc.module.subnets",
		},
		{
			address:      `aws_s3_bucket.buckets["data"]`,
			expectedType: "aws_s3_bucket",
			expectedName: "buckets",
			expectedKey:  "data",
			expectedMod:  "",
		},
		{
			address:      `aws_instance.web[0]`,
			expectedType: "aws_instance",
			expectedName: "web",
			expectedKey:  "0",
			expectedMod:  "",
		},
	}

	for _, tt := range tests {
		got, err := ParseTerraformAddress(tt.address)
		if err != nil {
			t.Fatalf("ParseTerraformAddress(%q) failed: %v", tt.address, err)
		}
		if got.Type != tt.expectedType {
			t.Errorf("expected type %q, got %q", tt.expectedType, got.Type)
		}
		if got.Name != tt.expectedName {
			t.Errorf("expected name %q, got %q", tt.expectedName, got.Name)
		}
		if got.Key != tt.expectedKey {
			t.Errorf("expected key %q, got %q", tt.expectedKey, got.Key)
		}
		if got.Module != tt.expectedMod {
			t.Errorf("expected module %q, got %q", tt.expectedMod, got.Module)
		}
	}
}
