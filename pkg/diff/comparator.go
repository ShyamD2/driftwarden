package diff

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/ShyamD2/driftwarden/pkg/models"
	"github.com/ShyamD2/driftwarden/pkg/normalizer"
)

// ComparatorOptions configures the 3-source drift correlation engine.
type ComparatorOptions struct {
	IncludeLowConfidence  bool
	IncludeSystemDefaults bool
	IgnoreEngine          *normalizer.IgnoreEngine
	Normalizer            *normalizer.Normalizer
}

// Comparator coordinates 3-source correlation across Desired (D), State (S), and Live (L).
type Comparator struct {
	opts ComparatorOptions
}

// NewComparator creates a new Comparator.
func NewComparator(opts ComparatorOptions) *Comparator {
	if opts.Normalizer == nil {
		opts.Normalizer = normalizer.NewNormalizer(opts.IncludeSystemDefaults)
	}
	if opts.IgnoreEngine == nil {
		opts.IgnoreEngine = normalizer.NewIgnoreEngine(nil)
	}
	return &Comparator{opts: opts}
}

type resourceTriple struct {
	Desired *models.CanonicalResource
	State   *models.CanonicalResource
	Live    *models.CanonicalResource
}

// Correlate executes 3-source drift correlation and compiles the ScanReport.
func (c *Comparator) Correlate(
	desired []models.CanonicalResource,
	state []models.CanonicalResource,
	live []models.CanonicalResource,
	scanID string,
	accountID string,
	regions []string,
) *models.ScanReport {
	startTime := time.Now()

	// Normalize resources
	for i := range desired {
		c.opts.Normalizer.Normalize(&desired[i])
	}
	for i := range state {
		c.opts.Normalizer.Normalize(&state[i])
	}
	for i := range live {
		c.opts.Normalizer.Normalize(&live[i])
	}

	triples := make(map[string]*resourceTriple)

	for i := range desired {
		r := &desired[i]
		id := correlationKey(*r)
		if _, ok := triples[id]; !ok {
			triples[id] = &resourceTriple{}
		}
		triples[id].Desired = r
	}

	for i := range state {
		r := &state[i]
		id := correlationKey(*r)
		if _, ok := triples[id]; !ok {
			triples[id] = &resourceTriple{}
		}
		triples[id].State = r
	}

	for i := range live {
		r := &live[i]
		id := correlationKey(*r)
		if _, ok := triples[id]; !ok {
			triples[id] = &resourceTriple{}
		}
		triples[id].Live = r
	}

	report := &models.ScanReport{
		ReportSchemaVersion: "1.0.0",
		ToolVersion:         "1.0.0",
		ScanID:              scanID,
		Timestamp:           time.Now().UTC().Format(time.RFC3339),
		AccountID:           accountID,
		Regions:             regions,
		SnapshotMode:        "CURRENT",
		Status:              "COMPLETE",
		TotalScanned:        len(triples),
		Items:               make([]models.DriftItem, 0),
		Summary:             make(map[models.DriftType]int),
	}

	for _, triple := range triples {
		item, isPartial := c.correlateTriple(triple)

		if isPartial {
			report.Status = "PARTIAL_SCAN"
			report.AccessDeniedCount++
			continue
		}

		if item == nil || item.Type == models.DriftInSync {
			continue
		}

		// Filter system defaults if --include-system-defaults == false
		if c.opts.Normalizer.ShouldSuppressSystemDefault(item.Resource) {
			continue
		}

		// Calculate Finding Confidence
		c.calculateConfidence(item, triple)

		// Low confidence suppression (< 0.5)
		if item.FindingConfidence < 0.5 && !c.opts.IncludeLowConfidence {
			item.FindingEvidence = append(item.FindingEvidence, "LOW_CONFIDENCE_SUPPRESSED (< 0.5)")
			continue
		}

		report.Items = append(report.Items, *item)
		report.Summary[item.Type]++
	}

	report.TotalDrift = len(report.Items)
	report.ExecutionTimeMs = time.Since(startTime).Milliseconds()

	return report
}

func correlationKey(res models.CanonicalResource) string {
	if res.CanonicalID != "" {
		return res.CanonicalID
	}
	return fmt.Sprintf("%s:%s:%s", res.Type, res.Region, res.ProviderID)
}

func (c *Comparator) correlateTriple(triple *resourceTriple) (*models.DriftItem, bool) {
	d := triple.Desired
	s := triple.State
	l := triple.Live

	// Case 1: State PRESENT, Live UNAVAILABLE (AccessDenied boundary)
	if s != nil && s.Availability == models.AvailabilityPresent &&
		l != nil && l.Availability == models.AvailabilityUnavailable {
		// Evaluate to UNKNOWN (Do NOT emit DriftGhost).
		// Mark ScanReport.Status = "PARTIAL_SCAN", Increment AccessDeniedCount.
		return nil, true
	}

	// Case 2: State PRESENT, Live ABSENT (DriftGhost)
	if s != nil && s.Availability == models.AvailabilityPresent &&
		(l == nil || l.Availability == models.AvailabilityAbsent) {
		item := &models.DriftItem{
			Resource:          *s,
			Type:              models.DriftGhost,
			Severity:          models.SeverityHigh,
			Diffs:             make(map[string]models.DiffDetail),
			FindingConfidence: 1.0,
			FindingEvidence:   []string{"resource present in Terraform state but absent in live AWS environment"},
		}
		return item, false
	}

	// Case 3: Desired ABSENT, State ABSENT, Live PRESENT (DriftShadow)
	if (d == nil || d.Availability == models.AvailabilityAbsent) &&
		(s == nil || s.Availability == models.AvailabilityAbsent) &&
		(l != nil && l.Availability == models.AvailabilityPresent) {
		item := &models.DriftItem{
			Resource:          *l,
			Type:              models.DriftShadow,
			Severity:          models.SeverityHigh,
			Diffs:             make(map[string]models.DiffDetail),
			FindingConfidence: 1.0,
			FindingEvidence:   []string{"unmanaged rogue cloud resource found in AWS without state or configuration"},
		}
		return item, false
	}

	// Case 4: Desired PRESENT, State PRESENT, Live PRESENT
	if d != nil && d.Availability == models.AvailabilityPresent &&
		s != nil && s.Availability == models.AvailabilityPresent &&
		l != nil && l.Availability == models.AvailabilityPresent {

		diffs, dEqualsS, sEqualsL := c.compareAttributes(d, s, l)

		// Correlation Matrix:
		// D == S && S == L -> DriftInSync
		// D == S && S != L -> DriftAttribute
		// D != S && S == L -> DriftUnappliedConfig
		// D != S && S != L -> DriftSplitBrain
		if dEqualsS && sEqualsL {
			return nil, false // InSync
		}

		var driftType models.DriftType
		var severity models.Severity

		if dEqualsS && !sEqualsL {
			driftType = models.DriftAttribute
			severity = models.SeverityMedium
		} else if !dEqualsS && sEqualsL {
			driftType = models.DriftUnappliedConfig
			severity = models.SeverityLow
		} else {
			driftType = models.DriftSplitBrain
			severity = models.SeverityCritical
		}

		item := &models.DriftItem{
			Resource:          *l,
			Type:              driftType,
			Severity:          severity,
			Diffs:             diffs,
			FindingConfidence: 1.0,
			FindingEvidence:   []string{fmt.Sprintf("3-source divergence detected: %s", driftType)},
		}
		return item, false
	}

	return nil, false
}

func (c *Comparator) compareAttributes(
	d *models.CanonicalResource,
	s *models.CanonicalResource,
	l *models.CanonicalResource,
) (map[string]models.DiffDetail, bool, bool) {
	diffs := make(map[string]models.DiffDetail)
	dEqualsS := true
	sEqualsL := true

	// Extract declared lifecycle ignores from desired/state attributes
	var lifecycleIgnores []string
	if ign, ok := d.Attributes["_ignore_changes"].([]string); ok {
		lifecycleIgnores = ign
	} else if ign, ok := s.Attributes["_ignore_changes"].([]string); ok {
		lifecycleIgnores = ign
	}

	// Extract attribute kinds from Desired attributes
	var attrKinds map[string]models.AttributeValueKind
	if k, ok := d.Attributes["_attribute_kinds"].(map[string]models.AttributeValueKind); ok {
		attrKinds = k
	}

	// Collect union of attribute keys
	allKeys := make(map[string]bool)
	for k := range d.Attributes {
		allKeys[k] = true
	}
	for k := range s.Attributes {
		allKeys[k] = true
	}
	for k := range l.Attributes {
		allKeys[k] = true
	}

	for k := range allKeys {
		if strings.HasPrefix(k, "_") {
			continue
		}
		if normalizer.ComputedAttributesToStrip[k] {
			continue
		}

		// Check Policy-as-Code Ignore Engine & lifecycle.ignore_changes
		if c.opts.IgnoreEngine.ShouldIgnore(d.Type, d.Name, k, lifecycleIgnores) {
			continue
		}

		kind := models.AttributeLiteral
		if attrKinds != nil {
			if specifiedKind, ok := attrKinds[k]; ok {
				kind = specifiedKind
			}
		}

		// A. Attribute Level Handling:
		// If Desired.AttributeKind is AttributeExpression, AttributeReference, or AttributeUnknown:
		// Skip attribute comparison for that key.
		// Record in diffs[key].ResolutionStatus = "UNRESOLVED_DESIRED_VALUE".
		// Do NOT emit ATTRIBUTE_DRIFT or SPLIT_BRAIN_DRIFT for that attribute!
		if kind == models.AttributeExpression || kind == models.AttributeReference || kind == models.AttributeUnknown {
			diffs[k] = models.DiffDetail{
				DesiredValue:     d.Attributes[k],
				StateValue:       s.Attributes[k],
				LiveValue:        l.Attributes[k],
				AttributeKind:    kind,
				ResolutionStatus: "UNRESOLVED_DESIRED_VALUE",
			}
			continue
		}

		dVal := d.Attributes[k]
		sVal := s.Attributes[k]
		lVal := l.Attributes[k]

		// Sensitive attributes handling
		if normalizer.IsSensitiveAttribute(k) {
			sMatchesL := normalizer.CompareSensitiveAttributes(sVal, lVal)
			dMatchesS := normalizer.CompareSensitiveAttributes(dVal, sVal)
			if !sMatchesL {
				sEqualsL = false
				diffs[k] = models.DiffDetail{
					DesiredValue:  normalizer.RedactedPlaceholder,
					StateValue:    normalizer.RedactedPlaceholder,
					LiveValue:     normalizer.RedactedPlaceholder,
					AttributeKind: kind,
				}
			}
			if !dMatchesS {
				dEqualsS = false
			}
			continue
		}

		// Default value equivalence
		dsMatch := reflect.DeepEqual(dVal, sVal) ||
			(dVal == nil && normalizer.IsEquivalentToDefault(d.Type, k, sVal)) ||
			(sVal == nil && normalizer.IsEquivalentToDefault(d.Type, k, dVal))

		slMatch := reflect.DeepEqual(sVal, lVal) ||
			(sVal == nil && normalizer.IsEquivalentToDefault(s.Type, k, lVal)) ||
			(lVal == nil && normalizer.IsEquivalentToDefault(s.Type, k, sVal))

		if !dsMatch {
			dEqualsS = false
		}
		if !slMatch {
			sEqualsL = false
		}

		if !dsMatch || !slMatch {
			diffs[k] = models.DiffDetail{
				DesiredValue:  dVal,
				StateValue:    sVal,
				LiveValue:     lVal,
				AttributeKind: kind,
			}
		}
	}

	return diffs, dEqualsS, sEqualsL
}

func (c *Comparator) calculateConfidence(item *models.DriftItem, triple *resourceTriple) {
	identityConf := item.Resource.IdentityConfidence
	if identityConf <= 0.0 {
		identityConf = 1.0
	}

	doubleReadFactor := 0.8
	if item.DoubleReadVerified {
		doubleReadFactor = 1.0
	}

	var availFactor float64
	if item.Type == models.DriftGhost {
		// For DriftGhost: AvailabilityFactor = (State.Availability == PRESENT ? 1.0 : 0.5)
		if triple.State != nil && triple.State.Availability == models.AvailabilityPresent {
			availFactor = 1.0
		} else {
			availFactor = 0.5
		}
	} else {
		// For all other drift types: AvailabilityFactor = (Live.Availability == PRESENT ? 1.0 : 0.5)
		if triple.Live != nil && triple.Live.Availability == models.AvailabilityPresent {
			availFactor = 1.0
		} else {
			availFactor = 0.5
		}
	}

	item.FindingConfidence = identityConf * doubleReadFactor * availFactor
}
