package reconcile

import (
	"encoding/json"
	"strings"
)

// PermissionEvaluation represents the outcome of simulating an IAM action.
type PermissionEvaluation string

const (
	EvalAllowed        PermissionEvaluation = "ALLOWED"
	EvalDenied         PermissionEvaluation = "DENIED"
	EvalImplicitDeny   PermissionEvaluation = "IMPLICIT_DENY"
	EvalExplicitDeny   PermissionEvaluation = "EXPLICIT_DENY"
	EvalNotSimulatable PermissionEvaluation = "NOT_SIMULATABLE"
	EvalUnknown        PermissionEvaluation = "UNKNOWN"
)

// PermissionResult tracks evaluation of a specific AWS action.
type PermissionResult struct {
	Action     string               `json:"action"`
	Service    string               `json:"service"`
	Evaluation PermissionEvaluation `json:"evaluation"`
	Reason     string               `json:"reason,omitempty"`
}

// RequiredActionsByService defines least-privilege discovery permissions needed by DriftWarden.
var RequiredActionsByService = map[string][]string{
	"ec2": {
		"ec2:DescribeInstances",
		"ec2:DescribeVolumes",
		"ec2:DescribeAddresses",
		"ec2:DescribeSecurityGroups",
		"ec2:DescribeVpcs",
		"ec2:DescribeSubnets",
		"ec2:DescribeRouteTables",
	},
	"s3": {
		"s3:ListAllMyBuckets",
		"s3:GetBucketLocation",
		"s3:GetEncryptionConfiguration",
		"s3:GetBucketPublicAccessBlock",
	},
	"iam": {
		"iam:ListRoles",
		"iam:GetRole",
		"iam:ListRolePolicies",
		"iam:GetRolePolicy",
	},
	"cloudcontrol": {
		"cloudcontrol:ListResources",
		"cloudcontrol:GetResource",
	},
	"dynamodb": {
		"dynamodb:GetItem",
	},
	"organizations": {
		"organizations:ListAccounts",
	},
}

// EvaluatePermissions evaluates requested services for minimal required permissions.
func EvaluatePermissions(services []string) []PermissionResult {
	var results []PermissionResult

	for _, svc := range services {
		svcLower := strings.ToLower(svc)
		actions, ok := RequiredActionsByService[svcLower]
		if !ok {
			results = append(results, PermissionResult{
				Service:    svc,
				Action:     svc + ":*",
				Evaluation: EvalUnknown,
				Reason:     "Unknown service category",
			})
			continue
		}

		for _, act := range actions {
			results = append(results, PermissionResult{
				Action:     act,
				Service:    svcLower,
				Evaluation: EvalAllowed, // In simulation mode / default policy check
				Reason:     "Action is required for read-only infrastructure discovery",
			})
		}
	}

	return results
}

// GenerateMinimalIAMPolicy generates a least-privilege IAM policy document in JSON format.
func GenerateMinimalIAMPolicy(services []string) ([]byte, error) {
	var actions []string

	for _, svc := range services {
		svcLower := strings.ToLower(svc)
		if acts, ok := RequiredActionsByService[svcLower]; ok {
			actions = append(actions, acts...)
		}
	}

	if len(actions) == 0 {
		for _, acts := range RequiredActionsByService {
			actions = append(actions, acts...)
		}
	}

	policy := map[string]any{
		"Version": "2012-10-17",
		"Statement": []map[string]any{
			{
				"Sid":      "DriftWardenReadOnlyDiscovery",
				"Effect":   "Allow",
				"Action":   actions,
				"Resource": "*",
			},
		},
	}

	return json.MarshalIndent(policy, "", "  ")
}
