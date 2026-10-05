package identity

import (
	"fmt"
	"strings"
)

// Supported 9 Core Resource Types.
const (
	TypeAWSInstance      = "aws_instance"
	TypeAWSEBSVolume     = "aws_ebs_volume"
	TypeAWSEIP           = "aws_eip"
	TypeAWSSecurityGroup = "aws_security_group"
	TypeAWSVPC           = "aws_vpc"
	TypeAWSSubnet        = "aws_subnet"
	TypeAWSRouteTable    = "aws_route_table"
	TypeAWSS3Bucket      = "aws_s3_bucket"
	TypeAWSIAMRole       = "aws_iam_role"
)

// ResourceIdentityRule defines how a Terraform resource maps to AWS canonical attributes.
type ResourceIdentityRule struct {
	TerraformType       string
	Service             string
	CanonicalType       string
	Global              bool
	OmitRegion          bool
	OmitAccount         bool
	ProviderIDPrefix    string
	ProviderIDAttribute string
}

// CoreResourceRules maps each of the 9 core AWS resource types to their canonical identity definition.
var CoreResourceRules = map[string]ResourceIdentityRule{
	TypeAWSInstance: {
		TerraformType:       TypeAWSInstance,
		Service:             "ec2",
		CanonicalType:       "instance",
		ProviderIDPrefix:    "i-",
		ProviderIDAttribute: "id",
	},
	TypeAWSEBSVolume: {
		TerraformType:       TypeAWSEBSVolume,
		Service:             "ec2",
		CanonicalType:       "volume",
		ProviderIDPrefix:    "vol-",
		ProviderIDAttribute: "id",
	},
	TypeAWSEIP: {
		TerraformType:       TypeAWSEIP,
		Service:             "ec2",
		CanonicalType:       "elastic-ip",
		ProviderIDPrefix:    "eipalloc-",
		ProviderIDAttribute: "allocation_id",
	},
	TypeAWSSecurityGroup: {
		TerraformType:       TypeAWSSecurityGroup,
		Service:             "ec2",
		CanonicalType:       "security-group",
		ProviderIDPrefix:    "sg-",
		ProviderIDAttribute: "id",
	},
	TypeAWSVPC: {
		TerraformType:       TypeAWSVPC,
		Service:             "ec2",
		CanonicalType:       "vpc",
		ProviderIDPrefix:    "vpc-",
		ProviderIDAttribute: "id",
	},
	TypeAWSSubnet: {
		TerraformType:       TypeAWSSubnet,
		Service:             "ec2",
		CanonicalType:       "subnet",
		ProviderIDPrefix:    "subnet-",
		ProviderIDAttribute: "id",
	},
	TypeAWSRouteTable: {
		TerraformType:       TypeAWSRouteTable,
		Service:             "ec2",
		CanonicalType:       "route-table",
		ProviderIDPrefix:    "rtb-",
		ProviderIDAttribute: "id",
	},
	TypeAWSS3Bucket: {
		TerraformType:       TypeAWSS3Bucket,
		Service:             "s3",
		CanonicalType:       "bucket",
		Global:              true,
		OmitRegion:          true,
		OmitAccount:         true,
		ProviderIDAttribute: "bucket",
	},
	TypeAWSIAMRole: {
		TerraformType:       TypeAWSIAMRole,
		Service:             "iam",
		CanonicalType:       "role",
		Global:              true,
		OmitRegion:          true,
		OmitAccount:         false,
		ProviderIDAttribute: "name",
	},
}

// IsCoreType checks if a given Terraform type is one of the 9 core types.
func IsCoreType(resType string) bool {
	_, ok := CoreResourceRules[resType]
	return ok
}

// CoreTypes returns a slice containing the names of all 9 core types.
func CoreTypes() []string {
	return []string{
		TypeAWSInstance,
		TypeAWSEBSVolume,
		TypeAWSEIP,
		TypeAWSSecurityGroup,
		TypeAWSVPC,
		TypeAWSSubnet,
		TypeAWSRouteTable,
		TypeAWSS3Bucket,
		TypeAWSIAMRole,
	}
}

// CanonicalComponentsForType constructs CanonicalComponents according to the rules for the 9 core types.
func CanonicalComponentsForType(resType, region, accountID, providerID string) (CanonicalComponents, error) {
	rule, ok := CoreResourceRules[resType]
	if !ok {
		// Fallback for custom or future resources
		cleanType := strings.TrimPrefix(resType, "aws_")
		return CanonicalComponents{
			Partition:    "aws",
			Service:      "aws",
			Region:       region,
			AccountID:    accountID,
			ResourceType: cleanType,
			ResourceID:   providerID,
		}, nil
	}

	comp := CanonicalComponents{
		Partition:    "aws",
		Service:      rule.Service,
		ResourceType: rule.CanonicalType,
		ResourceID:   providerID,
	}

	if !rule.OmitRegion {
		comp.Region = region
	}
	if !rule.OmitAccount {
		comp.AccountID = accountID
	}

	if comp.ResourceID == "" {
		return comp, fmt.Errorf("provider ID is required to generate canonical ID for %s", resType)
	}

	return comp, nil
}

// CanonicalIDForType generates the deterministic Canonical ID URN for a given core resource.
func CanonicalIDForType(resType, region, accountID, providerID string) string {
	comp, err := CanonicalComponentsForType(resType, region, accountID, providerID)
	if err != nil {
		return ""
	}
	return GenerateCanonicalID(comp)
}
