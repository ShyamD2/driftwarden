package identity

import (
	"fmt"

	"github.com/ShyamD2/driftwarden/pkg/models"
)

// IdentityResolver resolves canonical identity and correlates resources across Desired, State, and Live planes.
type IdentityResolver struct {
	DefaultPartition string
	DefaultRegion    string
	DefaultAccountID string
}

// NewResolver initializes an IdentityResolver with default AWS context.
func NewResolver(defaultRegion, defaultAccountID string) *IdentityResolver {
	return &IdentityResolver{
		DefaultPartition: "aws",
		DefaultRegion:    defaultRegion,
		DefaultAccountID: defaultAccountID,
	}
}

// ResolveFromState creates a CanonicalResource from a Terraform state entry.
func (r *IdentityResolver) ResolveFromState(
	tfType string,
	tfName string,
	region string,
	accountID string,
	attributes map[string]any,
	tags map[string]string,
) (models.CanonicalResource, error) {
	effectiveRegion := region
	if effectiveRegion == "" {
		effectiveRegion = r.DefaultRegion
	}
	effectiveAccount := accountID
	if effectiveAccount == "" {
		effectiveAccount = r.DefaultAccountID
	}

	stateIdent := ExtractStateIdentity(tfType, attributes)
	providerID := stateIdent.ProviderID

	canonicalID := ""
	if providerID != "" {
		canonicalID = CanonicalIDForType(tfType, effectiveRegion, effectiveAccount, providerID)
	}

	evidence := make([]string, 0, len(stateIdent.Evidence)+1)
	evidence = append(evidence, stateIdent.Evidence...)
	if canonicalID != "" {
		evidence = append(evidence, fmt.Sprintf("canonical URN generated: %s", canonicalID))
	}

	return models.CanonicalResource{
		CanonicalID:        canonicalID,
		Type:               tfType,
		ProviderID:         providerID,
		Name:               tfName,
		AccountID:          effectiveAccount,
		Region:             effectiveRegion,
		Attributes:         attributes,
		Tags:               tags,
		Source:             models.SourceState,
		Availability:       stateIdent.Availability,
		IdentityConfidence: stateIdent.Confidence,
		IdentityEvidence:   evidence,
	}, nil
}

// ResolveFromLive creates a CanonicalResource from an observed live AWS resource.
func (r *IdentityResolver) ResolveFromLive(
	tfType string,
	name string,
	region string,
	accountID string,
	providerID string,
	attributes map[string]any,
	tags map[string]string,
) (models.CanonicalResource, error) {
	effectiveRegion := region
	if effectiveRegion == "" {
		effectiveRegion = r.DefaultRegion
	}
	effectiveAccount := accountID
	if effectiveAccount == "" {
		effectiveAccount = r.DefaultAccountID
	}

	canonicalID := CanonicalIDForType(tfType, effectiveRegion, effectiveAccount, providerID)

	evidence := []string{
		fmt.Sprintf("observed directly from AWS provider api for %s with provider id %s", tfType, providerID),
		fmt.Sprintf("canonical URN generated: %s", canonicalID),
	}

	return models.CanonicalResource{
		CanonicalID:        canonicalID,
		Type:               tfType,
		ProviderID:         providerID,
		Name:               name,
		AccountID:          effectiveAccount,
		Region:             effectiveRegion,
		Attributes:         attributes,
		Tags:               tags,
		Source:             models.SourceLive,
		Availability:       models.AvailabilityPresent,
		IdentityConfidence: 1.0,
		IdentityEvidence:   evidence,
	}, nil
}

// MatchResources compares two CanonicalResources for identity equivalence.
// INVARIANT: Equivalent AWS resources MUST produce byte-for-byte identical CanonicalIDs.
func MatchResources(a, b models.CanonicalResource) bool {
	if a.CanonicalID == "" || b.CanonicalID == "" {
		return false
	}
	return a.CanonicalID == b.CanonicalID
}
