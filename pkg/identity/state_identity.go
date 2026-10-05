package identity

import (
	"fmt"
	"strings"

	"github.com/ShyamD2/driftwarden/pkg/models"
)

// StateIdentityResult captures the extracted identity details from Terraform state attributes.
type StateIdentityResult struct {
	ProviderID   string
	ARN          string
	Confidence   float64
	Availability models.ResourceAvailability
	Evidence     []string
}

// ExtractStateIdentity extracts the provider ID and identity metadata from state attributes
// using the explicit precedence:
// 1. If arn is present and non-empty/parseable -> use ARN (confidence = 1.0).
// 2. Else if id is present and non-empty -> use ID (confidence = 1.0).
// 3. Else if name is present and non-empty -> use name (confidence = 0.8).
// 4. Else -> AvailabilityUnknown (confidence = 0.4).
func ExtractStateIdentity(resType string, attributes map[string]any) StateIdentityResult {
	if attributes == nil {
		return StateIdentityResult{
			ProviderID:   "",
			ARN:          "",
			Confidence:   0.4,
			Availability: models.AvailabilityUnknown,
			Evidence:     []string{"no attributes provided in state"},
		}
	}

	// 1. Check ARN precedence
	if arnVal, ok := attributes["arn"]; ok && arnVal != nil {
		if arnStr, ok := arnVal.(string); ok && strings.TrimSpace(arnStr) != "" {
			trimmedARN := strings.TrimSpace(arnStr)
			providerID := extractProviderIDFromARN(resType, trimmedARN)
			if providerID == "" {
				// If we couldn't parse specific provider ID from ARN, fall back to the whole ARN or id
				providerID = trimmedARN
			}
			return StateIdentityResult{
				ProviderID:   providerID,
				ARN:          trimmedARN,
				Confidence:   1.0,
				Availability: models.AvailabilityPresent,
				Evidence:     []string{fmt.Sprintf("resolved from arn attribute: %s", trimmedARN)},
			}
		}
	}

	// 2. Check ID precedence
	if idVal, ok := attributes["id"]; ok && idVal != nil {
		if idStr, ok := idVal.(string); ok && strings.TrimSpace(idStr) != "" {
			trimmedID := strings.TrimSpace(idStr)
			return StateIdentityResult{
				ProviderID:   trimmedID,
				ARN:          "",
				Confidence:   1.0,
				Availability: models.AvailabilityPresent,
				Evidence:     []string{fmt.Sprintf("resolved from id attribute: %s", trimmedID)},
			}
		}
	}

	// 3. Check Name precedence
	for _, nameKey := range []string{"name", "bucket", "role_name", "group_name"} {
		if nameVal, ok := attributes[nameKey]; ok && nameVal != nil {
			if nameStr, ok := nameVal.(string); ok && strings.TrimSpace(nameStr) != "" {
				trimmedName := strings.TrimSpace(nameStr)
				return StateIdentityResult{
					ProviderID:   trimmedName,
					ARN:          "",
					Confidence:   0.8,
					Availability: models.AvailabilityPresent,
					Evidence:     []string{fmt.Sprintf("resolved from %s attribute (name fallback): %s", nameKey, trimmedName)},
				}
			}
		}
	}

	// 4. Fallback: AvailabilityUnknown (confidence = 0.4)
	return StateIdentityResult{
		ProviderID:   "",
		ARN:          "",
		Confidence:   0.4,
		Availability: models.AvailabilityUnknown,
		Evidence:     []string{"missing arn, id, and name attributes in state; unidentifiable resource"},
	}
}

// extractProviderIDFromARN extracts the core provider ID from a full AWS ARN.
// Example: arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789 -> i-0123456789
// Example: arn:aws:iam::123456789012:role/MyRole -> MyRole
// Example: arn:aws:s3:::example-bucket -> example-bucket
func extractProviderIDFromARN(resType, arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) < 6 {
		return ""
	}
	resPart := strings.Join(parts[5:], ":")
	if strings.Contains(resPart, "/") {
		slashParts := strings.Split(resPart, "/")
		return slashParts[len(slashParts)-1]
	}
	return resPart
}
