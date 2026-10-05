package v3

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ShyamD2/driftwarden/pkg/analyzer"
	"github.com/ShyamD2/driftwarden/pkg/models"
)

// DWCIS_EC2_001 verifies that no security group allows unrestricted ingress on port 22 (SSH).
type DWCIS_EC2_001 struct{}

func NewDWCIS_EC2_001() analyzer.SecurityRule {
	return &DWCIS_EC2_001{}
}

func (r *DWCIS_EC2_001) ID() string {
	return "DW-CIS-EC2-001"
}

func (r *DWCIS_EC2_001) BenchmarkVersion() string {
	return "CIS AWS Foundations Benchmark v3.0.0 (Section 5.2)"
}

func (r *DWCIS_EC2_001) Description() string {
	return "Ensure no security groups allow unrestricted ingress from 0.0.0.0/0 or ::/0 to port 22 (SSH)"
}

func (r *DWCIS_EC2_001) EvaluateResource(res models.CanonicalResource) (bool, models.Severity, string, string, error) {
	if res.Type != "aws_security_group" {
		return false, "", "", "", nil
	}

	ingressRules := extractIngressRules(res.Attributes)
	for _, rule := range ingressRules {
		if ruleAllowsPortAndUnrestrictedCIDR(rule, 22) {
			evidence := fmt.Sprintf("Security group allows unrestricted SSH ingress (port 22) from %s", rule.UnrestrictedCIDR)
			remediation := fmt.Sprintf("aws ec2 revoke-security-group-ingress --group-id %s --protocol tcp --port 22 --cidr %s", res.ProviderID, rule.UnrestrictedCIDR)
			return true, models.SeverityCritical, evidence, remediation, nil
		}
	}

	return false, "", "", "", nil
}

// DWCIS_EC2_002 verifies that no security group allows unrestricted ingress on port 3389 (RDP).
type DWCIS_EC2_002 struct{}

func NewDWCIS_EC2_002() analyzer.SecurityRule {
	return &DWCIS_EC2_002{}
}

func (r *DWCIS_EC2_002) ID() string {
	return "DW-CIS-EC2-002"
}

func (r *DWCIS_EC2_002) BenchmarkVersion() string {
	return "CIS AWS Foundations Benchmark v3.0.0 (Section 5.3)"
}

func (r *DWCIS_EC2_002) Description() string {
	return "Ensure no security groups allow unrestricted ingress from 0.0.0.0/0 or ::/0 to port 3389 (RDP)"
}

func (r *DWCIS_EC2_002) EvaluateResource(res models.CanonicalResource) (bool, models.Severity, string, string, error) {
	if res.Type != "aws_security_group" {
		return false, "", "", "", nil
	}

	ingressRules := extractIngressRules(res.Attributes)
	for _, rule := range ingressRules {
		if ruleAllowsPortAndUnrestrictedCIDR(rule, 3389) {
			evidence := fmt.Sprintf("Security group allows unrestricted RDP ingress (port 3389) from %s", rule.UnrestrictedCIDR)
			remediation := fmt.Sprintf("aws ec2 revoke-security-group-ingress --group-id %s --protocol tcp --port 3389 --cidr %s", res.ProviderID, rule.UnrestrictedCIDR)
			return true, models.SeverityCritical, evidence, remediation, nil
		}
	}

	return false, "", "", "", nil
}

type parsedSGRule struct {
	Protocol         string
	FromPort         int
	ToPort           int
	UnrestrictedCIDR string
	CIDRs            []string
}

func extractIngressRules(attrs map[string]any) []parsedSGRule {
	if attrs == nil {
		return nil
	}
	var results []parsedSGRule

	rawIngress, ok := attrs["ingress"]
	if !ok || rawIngress == nil {
		return nil
	}

	var ruleList []any
	switch v := rawIngress.(type) {
	case []any:
		ruleList = v
	case []map[string]any:
		for _, m := range v {
			ruleList = append(ruleList, m)
		}
	case map[string]any:
		ruleList = append(ruleList, v)
	}

	for _, item := range ruleList {
		ruleMap, ok := item.(map[string]any)
		if !ok {
			continue
		}

		protocol := fmt.Sprintf("%v", ruleMap["protocol"])
		fromPort := toInt(ruleMap["from_port"])
		toPort := toInt(ruleMap["to_port"])

		var cidrs []string
		if blocks, ok := ruleMap["cidr_blocks"].([]any); ok {
			for _, b := range blocks {
				cidrs = append(cidrs, fmt.Sprintf("%v", b))
			}
		} else if blocks, ok := ruleMap["cidr_blocks"].([]string); ok {
			cidrs = append(cidrs, blocks...)
		} else if b, ok := ruleMap["cidr_block"].(string); ok && b != "" {
			cidrs = append(cidrs, b)
		}

		if ipv6Blocks, ok := ruleMap["ipv6_cidr_blocks"].([]any); ok {
			for _, b := range ipv6Blocks {
				cidrs = append(cidrs, fmt.Sprintf("%v", b))
			}
		} else if ipv6Blocks, ok := ruleMap["ipv6_cidr_blocks"].([]string); ok {
			cidrs = append(cidrs, ipv6Blocks...)
		}

		var unrestricted string
		for _, c := range cidrs {
			cTrim := strings.TrimSpace(c)
			if cTrim == "0.0.0.0/0" || cTrim == "::/0" {
				unrestricted = cTrim
				break
			}
		}

		results = append(results, parsedSGRule{
			Protocol:         protocol,
			FromPort:         fromPort,
			ToPort:           toPort,
			UnrestrictedCIDR: unrestricted,
			CIDRs:            cidrs,
		})
	}

	return results
}

func ruleAllowsPortAndUnrestrictedCIDR(rule parsedSGRule, targetPort int) bool {
	if rule.UnrestrictedCIDR == "" {
		return false
	}

	if rule.Protocol == "-1" || rule.Protocol == "all" {
		return true
	}

	if rule.FromPort <= targetPort && rule.ToPort >= targetPort {
		return true
	}

	if rule.FromPort == 0 && rule.ToPort == 0 && (rule.Protocol == "-1" || rule.Protocol == "tcp") {
		return true
	}

	return false
}

func toInt(v any) int {
	if v == nil {
		return 0
	}
	switch val := v.(type) {
	case int:
		return val
	case int32:
		return int(val)
	case int64:
		return int(val)
	case float64:
		return int(val)
	case string:
		i, _ := strconv.Atoi(val)
		return i
	default:
		return 0
	}
}
