package normalizer

import (
	"reflect"
)

// DefaultValuesMap stores implicit provider defaults by resource type and attribute name.
// E.g., for aws_ebs_volume, encrypted=false is equivalent to omitting the attribute.
var DefaultValuesMap = map[string]map[string]any{
	"aws_ebs_volume": {
		"encrypted":   false,
		"iops":        float64(0),
		"volume_type": "gp2",
	},
	"aws_vpc": {
		"enable_dns_hostnames": false,
		"enable_dns_support":   true,
		"is_default":           false,
	},
	"aws_subnet": {
		"map_public_ip_on_launch": false,
		"default_for_az":          false,
	},
	"aws_security_group": {
		"is_default": false,
	},
	"aws_s3_bucket": {
		"server_side_encryption_enabled": false,
		"block_public_acls":              false,
		"block_public_policy":            false,
		"ignore_public_acls":             false,
		"restrict_public_buckets":        false,
	},
}

// IsEquivalentToDefault checks if a given value is equivalent to the provider's implicit default
// when the other side has omitted or nil for that attribute.
func IsEquivalentToDefault(resType, attrName string, val any) bool {
	if val == nil {
		return true
	}

	typeDefaults, ok := DefaultValuesMap[resType]
	if !ok {
		// Generic zero-value fallback
		return isZeroVal(val)
	}

	defaultVal, ok := typeDefaults[attrName]
	if !ok {
		return isZeroVal(val)
	}

	return reflect.DeepEqual(val, defaultVal) || isZeroVal(val)
}

func isZeroVal(val any) bool {
	if val == nil {
		return true
	}
	switch v := val.(type) {
	case bool:
		return !v
	case string:
		return v == ""
	case int:
		return v == 0
	case int32:
		return v == 0
	case int64:
		return v == 0
	case float64:
		return v == 0
	case []any:
		return len(v) == 0
	case map[string]any:
		return len(v) == 0
	default:
		return false
	}
}
