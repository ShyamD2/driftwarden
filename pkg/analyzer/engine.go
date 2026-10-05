package analyzer

import (
	"github.com/ShyamD2/driftwarden/pkg/models"
)

// SecurityEngine orchestrates evaluation of registered security and governance rules.
type SecurityEngine struct {
	rules []SecurityRule
}

// NewSecurityEngine creates a new empty SecurityEngine.
func NewSecurityEngine() *SecurityEngine {
	return &SecurityEngine{
		rules: make([]SecurityRule, 0),
	}
}

// RegisterRule adds a single rule to the engine.
func (e *SecurityEngine) RegisterRule(rule SecurityRule) {
	e.rules = append(e.rules, rule)
}

// RegisterRules adds multiple rules to the engine.
func (e *SecurityEngine) RegisterRules(rules ...SecurityRule) {
	e.rules = append(e.rules, rules...)
}

// Rules returns all registered rules.
func (e *SecurityEngine) Rules() []SecurityRule {
	return e.rules
}

// EvaluateResource evaluates all active rules for a single resource.
func (e *SecurityEngine) EvaluateResource(res models.CanonicalResource) []RuleResult {
	var results []RuleResult
	for _, rule := range e.rules {
		violation, sev, evidence, remediation, err := rule.EvaluateResource(res)
		if err != nil {
			continue
		}
		if violation {
			results = append(results, RuleResult{
				RuleID:           rule.ID(),
				BenchmarkVersion: rule.BenchmarkVersion(),
				Description:      rule.Description(),
				Severity:         sev,
				Passed:           false,
				Evidence:         evidence,
				Remediation:      remediation,
			})
		} else {
			results = append(results, RuleResult{
				RuleID:           rule.ID(),
				BenchmarkVersion: rule.BenchmarkVersion(),
				Description:      rule.Description(),
				Severity:         sev,
				Passed:           true,
			})
		}
	}
	return results
}

// AnalyzeReport evaluates security rules on all resources and drift items,
// annotates existing drift items with CIS rule violations, and creates security finding
// items for managed or unmanaged resources that violate security policies.
func (e *SecurityEngine) AnalyzeReport(
	report *models.ScanReport,
	allLiveResources []models.CanonicalResource,
	costProvider CostProvider,
) {
	if report == nil {
		return
	}
	if report.Summary == nil {
		report.Summary = make(map[models.DriftType]int)
	}

	// 1. Evaluate rules against existing drift items
	existingCIDs := make(map[string]int)
	for idx := range report.Items {
		item := &report.Items[idx]
		item.Capabilities.SecurityAnalyze = true
		existingCIDs[item.Resource.CanonicalID] = idx

		results := e.EvaluateResource(item.Resource)
		for _, res := range results {
			if !res.Passed {
				if item.CISRuleID == "" {
					item.CISRuleID = res.RuleID
				}
				if severityRank(res.Severity) > severityRank(item.Severity) {
					item.Severity = res.Severity
				}
				item.FindingEvidence = append(item.FindingEvidence, res.Evidence)
			}
		}
	}

	// 2. Evaluate rules against all live cloud state directly (including non-drifted resources)
	for _, res := range allLiveResources {
		results := e.EvaluateResource(res)
		for _, resResult := range results {
			if !resResult.Passed {
				// If this resource is not already an existing drift item, emit a security drift item
				if _, exists := existingCIDs[res.CanonicalID]; !exists {
					newItem := models.DriftItem{
						Resource:          res,
						Type:              models.DriftAttribute,
						Severity:          resResult.Severity,
						CISRuleID:         resResult.RuleID,
						Diffs:             make(map[string]models.DiffDetail),
						FindingConfidence: 1.0,
						FindingEvidence:   []string{resResult.Evidence},
						Capabilities: models.CollectorCapabilities{
							SecurityAnalyze: true,
						},
					}
					report.Items = append(report.Items, newItem)
					report.TotalDrift++
					report.Summary[models.DriftAttribute]++
					existingCIDs[res.CanonicalID] = len(report.Items) - 1
				}
			}
		}
	}

	// 3. Attach cost estimates
	if costProvider != nil {
		for idx := range report.Items {
			item := &report.Items[idx]
			item.Cost = costProvider.EstimateDriftWaste(item)
			item.Capabilities.CostEstimate = true
		}
	}
}

func severityRank(s models.Severity) int {
	switch s {
	case models.SeverityCritical:
		return 5
	case models.SeverityHigh:
		return 4
	case models.SeverityMedium:
		return 3
	case models.SeverityLow:
		return 2
	case models.SeverityInfo:
		return 1
	default:
		return 0
	}
}
