package v3

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/ShyamD2/driftwarden/pkg/analyzer"
	"github.com/ShyamD2/driftwarden/pkg/models"
)

// DWCIS_IAM_001 verifies that IAM roles do not grant unrestricted wildcard permissions (Action: "*").
type DWCIS_IAM_001 struct{}

func NewDWCIS_IAM_001() analyzer.SecurityRule {
	return &DWCIS_IAM_001{}
}

func (r *DWCIS_IAM_001) ID() string {
	return "DW-CIS-IAM-001"
}

func (r *DWCIS_IAM_001) BenchmarkVersion() string {
	return "CIS AWS Foundations Benchmark v3.0.0 (Section 1.16)"
}

func (r *DWCIS_IAM_001) Description() string {
	return "Ensure IAM role policy documents do not permit unrestricted administrative action wildcarding (*)"
}

type policyDoc struct {
	Statement any `json:"Statement"`
}

func (r *DWCIS_IAM_001) EvaluateResource(res models.CanonicalResource) (bool, models.Severity, string, string, error) {
	if res.Type != "aws_iam_role" {
		return false, "", "", "", nil
	}

	attrs := res.Attributes
	if attrs == nil {
		return false, "", "", "", nil
	}

	// Policy candidates to check
	var candidates []any
	for _, k := range []string{"policy", "assume_role_policy", "inline_policies"} {
		if val, ok := attrs[k]; ok && val != nil {
			candidates = append(candidates, val)
		}
	}

	highestSev := models.Severity("")
	worstEvidence := ""

	for _, cand := range candidates {
		stmts := extractStatements(cand)
		for _, stmt := range stmts {
			effect, _ := stmt["Effect"].(string)
			if !strings.EqualFold(effect, "Allow") {
				continue
			}

			actWildcard, serviceWildcard, actStr := analyzeActionWildcard(stmt["Action"])
			resWildcard := isFullWildcard(stmt["Resource"])

			var sev models.Severity
			var ev string

			if actWildcard && resWildcard {
				// Action: "*" and Resource: "*" -> CRITICAL
				sev = models.SeverityCritical
				ev = fmt.Sprintf("IAM role policy for %s contains unrestricted administrative wildcard Action: '*' with Resource: '*' (CRITICAL)", res.CanonicalID)
			} else if actWildcard {
				// Action: "*" on specific resource -> HIGH
				sev = models.SeverityHigh
				ev = fmt.Sprintf("IAM role policy for %s contains wildcard Action: '*' on specific resource %v (HIGH)", res.CanonicalID, stmt["Resource"])
			} else if serviceWildcard {
				// Action: "<service>:*" -> MEDIUM
				sev = models.SeverityMedium
				ev = fmt.Sprintf("IAM role policy for %s contains service-level wildcard Action: '%s' (MEDIUM)", res.CanonicalID, actStr)
			}

			if sev != "" {
				if highestSev == "" || rankSeverity(sev) > rankSeverity(highestSev) {
					highestSev = sev
					worstEvidence = ev
				}
			}
		}
	}

	if highestSev != "" {
		remediation := fmt.Sprintf("Scope down IAM policy permissions for role %s to least-privilege specific actions", res.ProviderID)
		return true, highestSev, worstEvidence, remediation, nil
	}

	return false, "", "", "", nil
}

func extractStatements(policyData any) []map[string]any {
	var stmts []map[string]any
	switch v := policyData.(type) {
	case string:
		decoded, err := url.QueryUnescape(v)
		if err == nil && decoded != "" {
			v = decoded
		}
		var doc policyDoc
		if err := json.Unmarshal([]byte(v), &doc); err == nil {
			return toStatementMaps(doc.Statement)
		}
	case map[string]any:
		return toStatementMaps(v["Statement"])
	case []any:
		for _, item := range v {
			stmts = append(stmts, extractStatements(item)...)
		}
	}
	return stmts
}

func toStatementMaps(stmtData any) []map[string]any {
	var stmts []map[string]any
	switch s := stmtData.(type) {
	case []any:
		for _, item := range s {
			if m, ok := item.(map[string]any); ok {
				stmts = append(stmts, m)
			}
		}
	case map[string]any:
		stmts = append(stmts, s)
	}
	return stmts
}

func analyzeActionWildcard(action any) (fullWildcard bool, serviceWildcard bool, actStr string) {
	switch a := action.(type) {
	case string:
		if a == "*" {
			return true, false, a
		}
		if strings.HasSuffix(a, ":*") {
			return false, true, a
		}
	case []any:
		for _, item := range a {
			if str, ok := item.(string); ok {
				if str == "*" {
					return true, false, str
				}
				if strings.HasSuffix(str, ":*") {
					serviceWildcard = true
					actStr = str
				}
			}
		}
	case []string:
		for _, str := range a {
			if str == "*" {
				return true, false, str
			}
			if strings.HasSuffix(str, ":*") {
				serviceWildcard = true
				actStr = str
			}
		}
	}
	return false, serviceWildcard, actStr
}

func isFullWildcard(resource any) bool {
	switch r := resource.(type) {
	case string:
		return r == "*"
	case []any:
		for _, item := range r {
			if str, ok := item.(string); ok && str == "*" {
				return true
			}
		}
	case []string:
		for _, str := range r {
			if str == "*" {
				return true
			}
		}
	}
	return false
}

func rankSeverity(s models.Severity) int {
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
