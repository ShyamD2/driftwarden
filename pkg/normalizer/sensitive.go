package normalizer

import (
	"strings"
)

// SensitiveAttributeNames lists attribute names and substrings identifying write-only or sensitive fields.
var SensitiveAttributeNames = []string{
	"password",
	"private_key",
	"secret_string",
	"secret_key",
	"token",
	"master_password",
	"admin_password",
	"certificate_private_key",
	"client_secret",
}

// RedactedPlaceholder is the string shown for redacted sensitive values.
const RedactedPlaceholder = "[REDACTED]"

// IsSensitiveAttribute checks if an attribute name represents a sensitive write-only field.
func IsSensitiveAttribute(attrName string) bool {
	lower := strings.ToLower(attrName)
	for _, sens := range SensitiveAttributeNames {
		if strings.Contains(lower, sens) {
			return true
		}
	}
	return false
}

// CompareSensitiveAttributes handles sensitive attribute verification:
// Sensitive fields are presence-verified only. If AWS returns empty-string or null while desired/state
// has a value, it is NOT flagged as drift because AWS does not echo back write-only sensitive fields.
func CompareSensitiveAttributes(stateVal, liveVal any) bool {
	// If both nil or empty, in sync
	if isZeroVal(stateVal) && isZeroVal(liveVal) {
		return true
	}

	// If state has a value, but live is empty/null/omitted, AWS suppresses read-back of write-only secrets:
	// Do NOT flag drift!
	if !isZeroVal(stateVal) && isZeroVal(liveVal) {
		return true
	}

	// If live has a value and state has a value, consider in sync (presence verified)
	if !isZeroVal(stateVal) && !isZeroVal(liveVal) {
		return true
	}

	// Live has a value but state does not
	return false
}

// RedactSensitiveValue returns the redacted placeholder if the attribute is sensitive.
func RedactSensitiveValue(attrName string, val any) any {
	if !IsSensitiveAttribute(attrName) || val == nil {
		return val
	}
	return RedactedPlaceholder
}
