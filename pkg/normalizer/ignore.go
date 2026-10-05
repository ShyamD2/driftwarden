package normalizer

import (
	"os"
	"path"
	"strings"

	"gopkg.in/yaml.v3"
)

// IgnoreRule defines an attribute suppression pattern.
type IgnoreRule struct {
	Resource   string   `yaml:"resource"`   // e.g. "aws_instance.*", "aws_security_group.web"
	Attributes []string `yaml:"attributes"` // e.g. ["tags", "ami"]
	Reason     string   `yaml:"reason,omitempty"`
}

// IgnoreFile represents the structure of .driftwardenignore YAML.
type IgnoreFile struct {
	Rules []IgnoreRule `yaml:"rules"`
}

// IgnoreEngine evaluates ignore rules from .driftwardenignore and lifecycle.ignore_changes.
type IgnoreEngine struct {
	Rules []IgnoreRule
}

// NewIgnoreEngine initializes an IgnoreEngine with given rules.
func NewIgnoreEngine(rules []IgnoreRule) *IgnoreEngine {
	return &IgnoreEngine{Rules: rules}
}

// LoadIgnoreFile parses a .driftwardenignore YAML file from disk. If the file does not exist,
// an empty IgnoreEngine is returned without error.
func LoadIgnoreFile(filePath string) (*IgnoreEngine, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return &IgnoreEngine{Rules: nil}, nil
		}
		return nil, err
	}

	var f IgnoreFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, err
	}

	return &IgnoreEngine{Rules: f.Rules}, nil
}

// ShouldIgnore checks if an attribute diff should be suppressed based on:
// 1. Any rule in .driftwardenignore matching the resource pattern.
// 2. Any declared lifecycle.ignore_changes for this resource.
func (ie *IgnoreEngine) ShouldIgnore(resType, resName, attrName string, declaredLifecycleIgnores []string) bool {
	// 1. Check lifecycle.ignore_changes first
	for _, ign := range declaredLifecycleIgnores {
		if strings.EqualFold(ign, attrName) || strings.EqualFold(ign, "all") {
			return true
		}
		// Match nested tags.* etc.
		if matched, _ := path.Match(ign, attrName); matched {
			return true
		}
	}

	if ie == nil || len(ie.Rules) == 0 {
		return false
	}

	fullAddress := resType + "." + resName

	// 2. Check .driftwardenignore rules
	for _, rule := range ie.Rules {
		matchedResource := false

		// Try exact match or glob match
		if rule.Resource == fullAddress || rule.Resource == resType || rule.Resource == "*" {
			matchedResource = true
		} else if matched, err := path.Match(rule.Resource, fullAddress); err == nil && matched {
			matchedResource = true
		} else if strings.HasSuffix(rule.Resource, ".*") {
			prefix := strings.TrimSuffix(rule.Resource, ".*")
			if prefix == resType {
				matchedResource = true
			}
		}

		if !matchedResource {
			continue
		}

		// Resource matched, check attribute list
		for _, attrRule := range rule.Attributes {
			if strings.EqualFold(attrRule, attrName) || attrRule == "*" {
				return true
			}
			if matched, _ := path.Match(attrRule, attrName); matched {
				return true
			}
		}
	}

	return false
}
