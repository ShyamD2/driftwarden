package terraform

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ShyamD2/driftwarden/pkg/identity"
	"github.com/ShyamD2/driftwarden/pkg/models"
)

// StateFile represents the root structure of Terraform State Schema v4.
type StateFile struct {
	Version          int             `json:"version"`
	TerraformVersion string          `json:"terraform_version"`
	Serial           int64           `json:"serial"`
	Lineage          string          `json:"lineage"`
	Resources        []StateResource `json:"resources"`
}

// StateResource represents an individual resource entry in state.
type StateResource struct {
	Module    string          `json:"module,omitempty"`
	Mode      string          `json:"mode"`
	Type      string          `json:"type"`
	Name      string          `json:"name"`
	Provider  string          `json:"provider"`
	Instances []StateInstance `json:"instances"`
}

// StateInstance represents a concrete provisioned instance of a resource.
type StateInstance struct {
	SchemaVersion int            `json:"schema_version"`
	IndexKey      any            `json:"index_key,omitempty"`
	Attributes    map[string]any `json:"attributes"`
}

// StateParser parses Terraform State Schema v4 into canonical resources.
type StateParser struct {
	DefaultRegion    string
	DefaultAccountID string
}

// NewStateParser creates a new StateParser.
func NewStateParser(defaultRegion, defaultAccountID string) *StateParser {
	return &StateParser{
		DefaultRegion:    defaultRegion,
		DefaultAccountID: defaultAccountID,
	}
}

// ParseFile parses a local state file.
func (sp *StateParser) ParseFile(filePath string) ([]models.CanonicalResource, *StateFile, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read state file %q: %w", filePath, err)
	}
	return sp.ParseBytes(data, filePath)
}

// ParseBytes parses state JSON from raw bytes.
func (sp *StateParser) ParseBytes(data []byte, origin string) ([]models.CanonicalResource, *StateFile, error) {
	var state StateFile
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal state file %s: %w", origin, err)
	}

	if state.Version != 4 {
		return nil, nil, fmt.Errorf("unsupported state schema version %d in %s (expected version 4)", state.Version, origin)
	}

	canonicalResources := make([]models.CanonicalResource, 0)

	for _, res := range state.Resources {
		// Drift detection focuses on managed resources
		if res.Mode != "managed" {
			continue
		}

		for _, inst := range res.Instances {
			canRes := sp.mapInstanceToCanonical(res, inst, origin)
			canonicalResources = append(canonicalResources, canRes)
		}
	}

	return canonicalResources, &state, nil
}

func (sp *StateParser) mapInstanceToCanonical(res StateResource, inst StateInstance, origin string) models.CanonicalResource {
	attrs := inst.Attributes
	if attrs == nil {
		attrs = make(map[string]any)
	}

	// 1. Extract identity via Phase 1 precedence rules
	identResult := identity.ExtractStateIdentity(res.Type, attrs)

	// 2. Resolve Region and AccountID
	effectiveRegion := sp.DefaultRegion
	effectiveAccount := sp.DefaultAccountID

	// Check if ARN is present and provides region/account
	if identResult.ARN != "" {
		parts := strings.Split(identResult.ARN, ":")
		if len(parts) >= 6 {
			arnRegion := parts[3]
			arnAccount := parts[4]
			if arnRegion != "" {
				effectiveRegion = arnRegion
			}
			if arnAccount != "" {
				effectiveAccount = arnAccount
			}
		}
	} else {
		if rVal, ok := attrs["region"]; ok {
			if rStr, ok := rVal.(string); ok && rStr != "" {
				effectiveRegion = rStr
			}
		}
		if aVal, ok := attrs["account_id"]; ok {
			if aStr, ok := aVal.(string); ok && aStr != "" {
				effectiveAccount = aStr
			}
		}
	}

	// 3. Derive deterministic CanonicalID
	canonicalID := ""
	if identResult.ProviderID != "" {
		canonicalID = identity.CanonicalIDForType(res.Type, effectiveRegion, effectiveAccount, identResult.ProviderID)
	}

	// 4. Extract tags
	tags := make(map[string]string)
	if tagsVal, ok := attrs["tags"]; ok && tagsVal != nil {
		if tagMap, ok := tagsVal.(map[string]any); ok {
			for k, v := range tagMap {
				tags[k] = fmt.Sprintf("%v", v)
			}
		}
	}

	// 5. Construct Address
	var addrBuilder strings.Builder
	if res.Module != "" {
		addrBuilder.WriteString(res.Module)
		addrBuilder.WriteString(".")
	}
	addrBuilder.WriteString(res.Type)
	addrBuilder.WriteString(".")
	addrBuilder.WriteString(res.Name)
	if inst.IndexKey != nil {
		addrBuilder.WriteString(fmt.Sprintf("[%v]", inst.IndexKey))
	}
	address := addrBuilder.String()

	evidence := make([]string, 0, len(identResult.Evidence)+2)
	evidence = append(evidence, identResult.Evidence...)
	evidence = append(evidence, fmt.Sprintf("state origin: %s", origin))
	evidence = append(evidence, fmt.Sprintf("terraform address: %s", address))

	return models.CanonicalResource{
		CanonicalID:        canonicalID,
		Type:               res.Type,
		ProviderID:         identResult.ProviderID,
		Name:               res.Name,
		AccountID:          effectiveAccount,
		Region:             effectiveRegion,
		Attributes:         attrs,
		Tags:               tags,
		Source:             models.SourceState,
		Availability:       identResult.Availability,
		IdentityConfidence: identResult.Confidence,
		IdentityEvidence:   evidence,
	}
}
