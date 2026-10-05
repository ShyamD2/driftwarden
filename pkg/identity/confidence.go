package identity

import (
	"github.com/ShyamD2/driftwarden/pkg/models"
)

// CalculateFindingConfidence calculates the finding confidence as a pure mathematical formula:
//
// FindingConfidence = IdentityConfidence * (DoubleReadVerified ? 1.0 : 0.8) * (Availability == PRESENT ? 1.0 : 0.5)
//
// Invariants:
// - For DriftGhost: evaluates State availability.
// - For all other drift types: evaluates Live availability.
// - Phase 1 implements pure math only and MUST NOT perform drift suppression (suppression belongs to Phase 4).
func CalculateFindingConfidence(item models.DriftItem) float64 {
	identityConf := item.Resource.IdentityConfidence
	if identityConf <= 0.0 {
		identityConf = 1.0
	}

	avail := item.Resource.Availability

	// For DriftGhost, availability is determined by the State definition.
	// For other types, availability is determined by the Live observation.
	// Both use the resource availability associated with the item's evaluated plane.
	return CalculateConfidenceScore(identityConf, item.DoubleReadVerified, avail)
}

// CalculateConfidenceScore is the pure arithmetic calculation of the finding confidence formula.
func CalculateConfidenceScore(identityConfidence float64, doubleReadVerified bool, availability models.ResourceAvailability) float64 {
	doubleReadFactor := 0.8
	if doubleReadVerified {
		doubleReadFactor = 1.0
	}

	availabilityFactor := 0.5
	if availability == models.AvailabilityPresent {
		availabilityFactor = 1.0
	}

	return identityConfidence * doubleReadFactor * availabilityFactor
}
