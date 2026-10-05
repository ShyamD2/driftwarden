package terraform

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"

	"github.com/ShyamD2/driftwarden/pkg/identity"
	"github.com/ShyamD2/driftwarden/pkg/models"
)

// DesiredResource encapsulates a parsed HCL resource with its attribute categorization and lifecycle policies.
type DesiredResource struct {
	Resource       models.CanonicalResource
	AttributeKinds map[string]models.AttributeValueKind
	IgnoreChanges  []string
}

// ConfigParser parses Terraform HCL configurations into canonical desired resources.
type ConfigParser struct {
	DefaultRegion    string
	DefaultAccountID string
}

// NewConfigParser creates a new ConfigParser instance.
func NewConfigParser(defaultRegion, defaultAccountID string) *ConfigParser {
	return &ConfigParser{
		DefaultRegion:    defaultRegion,
		DefaultAccountID: defaultAccountID,
	}
}

// ParseDirectory parses all .tf files in the target directory into CanonicalResource slice.
func (cp *ConfigParser) ParseDirectory(dir string) ([]models.CanonicalResource, []DesiredResource, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read hcl directory %q: %w", dir, err)
	}

	canonicalResources := make([]models.CanonicalResource, 0)
	desiredResources := make([]DesiredResource, 0)

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tf") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		canRes, desRes, err := cp.ParseFile(path)
		if err != nil {
			return nil, nil, fmt.Errorf("error parsing %s: %w", path, err)
		}
		canonicalResources = append(canonicalResources, canRes...)
		desiredResources = append(desiredResources, desRes...)
	}

	return canonicalResources, desiredResources, nil
}

// ParseFile parses a single .tf file.
func (cp *ConfigParser) ParseFile(filePath string) ([]models.CanonicalResource, []DesiredResource, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read file %q: %w", filePath, err)
	}
	return cp.ParseBytes(content, filePath)
}

// ParseBytes parses HCL content provided as bytes.
func (cp *ConfigParser) ParseBytes(content []byte, filename string) ([]models.CanonicalResource, []DesiredResource, error) {
	parser := hclparse.NewParser()
	file, diags := parser.ParseHCL(content, filename)
	if diags != nil && diags.HasErrors() {
		return nil, nil, fmt.Errorf("hcl parse errors in %s: %s", filename, diags.Error())
	}

	syntaxBody, ok := file.Body.(*hclsyntax.Body)
	if !ok {
		return nil, nil, fmt.Errorf("unsupported HCL body structure in %s", filename)
	}

	canonicalList := make([]models.CanonicalResource, 0)
	desiredList := make([]DesiredResource, 0)

	for _, block := range syntaxBody.Blocks {
		if block.Type != "resource" {
			continue
		}
		if len(block.Labels) < 2 {
			continue
		}

		resType := block.Labels[0]
		resName := block.Labels[1]

		desRes := cp.parseResourceBlock(block, resType, resName, filename)
		desiredList = append(desiredList, desRes)
		canonicalList = append(canonicalList, desRes.Resource)
	}

	return canonicalList, desiredList, nil
}

func (cp *ConfigParser) parseResourceBlock(
	block *hclsyntax.Block,
	resType string,
	resName string,
	filename string,
) DesiredResource {
	attributes := make(map[string]any)
	attrKinds := make(map[string]models.AttributeValueKind)
	tags := make(map[string]string)
	ignoreChanges := make([]string, 0)

	// Parse direct attributes
	for name, attr := range block.Body.Attributes {
		val, kind := evaluateExpression(attr.Expr)
		attributes[name] = val
		attrKinds[name] = kind

		if name == "tags" {
			if tagMap, ok := val.(map[string]any); ok {
				for k, v := range tagMap {
					tags[k] = fmt.Sprintf("%v", v)
				}
			}
		}
	}

	// Parse nested blocks (lifecycle, tags, etc.)
	for _, nested := range block.Body.Blocks {
		if nested.Type == "lifecycle" {
			if icAttr, ok := nested.Body.Attributes["ignore_changes"]; ok {
				icVal, _ := evaluateExpression(icAttr.Expr)
				if list, ok := icVal.([]any); ok {
					for _, item := range list {
						ignoreChanges = append(ignoreChanges, fmt.Sprintf("%v", item))
					}
				}
			}
		}
	}

	// Embed metadata into attributes
	attributes["_attribute_kinds"] = attrKinds
	if len(ignoreChanges) > 0 {
		attributes["_ignore_changes"] = ignoreChanges
	}

	// Resolve provider ID if static id or name is present
	providerID := resName
	if idVal, ok := attributes["id"]; ok {
		if idStr, ok := idVal.(string); ok && idStr != "" {
			providerID = idStr
		}
	} else if bucketVal, ok := attributes["bucket"]; ok {
		if bStr, ok := bucketVal.(string); ok && bStr != "" {
			providerID = bStr
		}
	}

	canonicalID := identity.CanonicalIDForType(resType, cp.DefaultRegion, cp.DefaultAccountID, providerID)

	canonicalRes := models.CanonicalResource{
		CanonicalID:        canonicalID,
		Type:               resType,
		ProviderID:         providerID,
		Name:               resName,
		AccountID:          cp.DefaultAccountID,
		Region:             cp.DefaultRegion,
		Attributes:         attributes,
		Tags:               tags,
		Source:             models.SourceDesired,
		Availability:       models.AvailabilityPresent,
		IdentityConfidence: 1.0,
		IdentityEvidence: []string{
			fmt.Sprintf("parsed from HCL config file: %s", filepath.Base(filename)),
			fmt.Sprintf("resource address: %s.%s", resType, resName),
		},
	}

	return DesiredResource{
		Resource:       canonicalRes,
		AttributeKinds: attrKinds,
		IgnoreChanges:  ignoreChanges,
	}
}

// evaluateExpression categorizes an HCL expression into AttributeValueKind and extracts its value representation.
func evaluateExpression(expr hclsyntax.Expression) (any, models.AttributeValueKind) {
	if expr == nil {
		return nil, models.AttributeUnknown
	}

	switch e := expr.(type) {
	case *hclsyntax.LiteralValueExpr:
		return ctyValueToGo(e.Val), models.AttributeLiteral

	case *hclsyntax.ScopeTraversalExpr:
		ref := traversalToString(e.Traversal)
		return ref, models.AttributeReference

	case *hclsyntax.TupleConsExpr:
		list := make([]any, 0, len(e.Exprs))
		allLiteral := true
		hasReference := false

		for _, itemExpr := range e.Exprs {
			v, kind := evaluateExpression(itemExpr)
			list = append(list, v)
			if kind != models.AttributeLiteral {
				allLiteral = false
			}
			if kind == models.AttributeReference {
				hasReference = true
			}
		}

		if allLiteral {
			return list, models.AttributeLiteral
		}
		if hasReference {
			return list, models.AttributeReference
		}
		return list, models.AttributeExpression

	case *hclsyntax.ObjectConsExpr:
		objMap := make(map[string]any)
		allLiteral := true
		hasReference := false

		for _, item := range e.Items {
			keyVal, _ := evaluateExpression(item.KeyExpr)
			keyStr := fmt.Sprintf("%v", keyVal)
			val, kind := evaluateExpression(item.ValueExpr)
			objMap[keyStr] = val

			if kind != models.AttributeLiteral {
				allLiteral = false
			}
			if kind == models.AttributeReference {
				hasReference = true
			}
		}

		if allLiteral {
			return objMap, models.AttributeLiteral
		}
		if hasReference {
			return objMap, models.AttributeReference
		}
		return objMap, models.AttributeExpression

	case *hclsyntax.TemplateWrapExpr:
		return evaluateExpression(e.Wrapped)

	case *hclsyntax.TemplateExpr:
		if len(e.Parts) == 1 {
			return evaluateExpression(e.Parts[0])
		}
		// String with interpolation
		var sb strings.Builder
		hasRef := false
		for _, part := range e.Parts {
			pVal, pKind := evaluateExpression(part)
			sb.WriteString(fmt.Sprintf("%v", pVal))
			if pKind == models.AttributeReference {
				hasRef = true
			}
		}
		if hasRef {
			return sb.String(), models.AttributeReference
		}
		return sb.String(), models.AttributeExpression

	case *hclsyntax.FunctionCallExpr:
		return fmt.Sprintf("%s(...)", e.Name), models.AttributeExpression

	case *hclsyntax.ConditionalExpr:
		return "conditional_expression", models.AttributeExpression

	case *hclsyntax.BinaryOpExpr, *hclsyntax.UnaryOpExpr:
		return "operation_expression", models.AttributeExpression

	default:
		return "unknown_expression", models.AttributeUnknown
	}
}

func ctyValueToGo(val cty.Value) any {
	if !val.IsKnown() || val.IsNull() {
		return nil
	}
	switch val.Type() {
	case cty.Bool:
		return val.True()
	case cty.Number:
		bf := val.AsBigFloat()
		f, _ := bf.Float64()
		return f
	case cty.String:
		return val.AsString()
	default:
		if val.Type().IsListType() || val.Type().IsSetType() || val.Type().IsTupleType() {
			items := make([]any, 0)
			for it := val.ElementIterator(); it.Next(); {
				_, v := it.Element()
				items = append(items, ctyValueToGo(v))
			}
			return items
		}
		if val.Type().IsMapType() || val.Type().IsObjectType() {
			m := make(map[string]any)
			for it := val.ElementIterator(); it.Next(); {
				k, v := it.Element()
				m[k.AsString()] = ctyValueToGo(v)
			}
			return m
		}
		return val.GoString()
	}
}

func traversalToString(traversal hcl.Traversal) string {
	var parts []string
	for _, step := range traversal {
		switch s := step.(type) {
		case hcl.TraverseRoot:
			parts = append(parts, s.Name)
		case hcl.TraverseAttr:
			parts = append(parts, s.Name)
		case hcl.TraverseIndex:
			parts = append(parts, fmt.Sprintf("[%v]", ctyValueToGo(s.Key)))
		}
	}
	return strings.Join(parts, ".")
}
