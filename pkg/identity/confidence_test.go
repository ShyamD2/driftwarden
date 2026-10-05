package identity

import (
	"math"
	"testing"

	"github.com/ShyamD2/driftwarden/pkg/models"
)

func TestCalculateFindingConfidencePureMath(t *testing.T) {
	tests := []struct {
		name       string
		item       models.DriftItem
		wantFactor float64
	}{
		{
			name: "Identity 0.8, DoubleRead false, Availability PRESENT",
			item: models.DriftItem{
				Type:               models.DriftAttribute,
				DoubleReadVerified: false,
				Resource: models.CanonicalResource{
					IdentityConfidence: 0.8,
					Availability:       models.AvailabilityPresent,
				},
			},
			wantFactor: 0.64, // 0.8 * 0.8 * 1.0
		},
		{
			name: "Identity 0.4, DoubleRead false, Availability PRESENT (pure math, no suppression)",
			item: models.DriftItem{
				Type:               models.DriftAttribute,
				DoubleReadVerified: false,
				Resource: models.CanonicalResource{
					IdentityConfidence: 0.4,
					Availability:       models.AvailabilityPresent,
				},
			},
			wantFactor: 0.32, // 0.4 * 0.8 * 1.0
		},
		{
			name: "Identity 1.0, DoubleRead true, Availability PRESENT",
			item: models.DriftItem{
				Type:               models.DriftShadow,
				DoubleReadVerified: true,
				Resource: models.CanonicalResource{
					IdentityConfidence: 1.0,
					Availability:       models.AvailabilityPresent,
				},
			},
			wantFactor: 1.0, // 1.0 * 1.0 * 1.0
		},
		{
			name: "Identity 1.0, DoubleRead true, Availability UNAVAILABLE",
			item: models.DriftItem{
				Type:               models.DriftAttribute,
				DoubleReadVerified: true,
				Resource: models.CanonicalResource{
					IdentityConfidence: 1.0,
					Availability:       models.AvailabilityUnavailable,
				},
			},
			wantFactor: 0.5, // 1.0 * 1.0 * 0.5
		},
		{
			name: "Identity 1.0, DoubleRead false, Availability ABSENT",
			item: models.DriftItem{
				Type:               models.DriftAttribute,
				DoubleReadVerified: false,
				Resource: models.CanonicalResource{
					IdentityConfidence: 1.0,
					Availability:       models.AvailabilityAbsent,
				},
			},
			wantFactor: 0.4, // 1.0 * 0.8 * 0.5
		},
		{
			name: "DriftGhost with State Availability PRESENT",
			item: models.DriftItem{
				Type:               models.DriftGhost,
				DoubleReadVerified: true,
				Resource: models.CanonicalResource{
					Source:             models.SourceState,
					IdentityConfidence: 1.0,
					Availability:       models.AvailabilityPresent,
				},
			},
			wantFactor: 1.0, // 1.0 * 1.0 * 1.0
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculateFindingConfidence(tt.item)
			if math.Abs(got-tt.wantFactor) > 0.0001 {
				t.Errorf("CalculateFindingConfidence() = %f; want %f", got, tt.wantFactor)
			}
		})
	}
}
