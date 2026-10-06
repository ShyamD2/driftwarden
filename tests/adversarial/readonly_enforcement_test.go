package adversarial

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ForbiddenMutatingPrefixes lists all AWS SDK operation prefixes that represent mutations.
// DriftWarden guarantees mechanically that no collector or scanner component invokes any of these.
var ForbiddenMutatingPrefixes = []string{
	"Create",
	"Delete",
	"Update",
	"Put",
	"Modify",
	"Terminate",
	"Revoke",
	"Authorize",
	"Attach",
	"Detach",
	"Register",
	"Deregister",
	"Stop",
	"Start",
	"Reboot",
}

// AllowedReadOnlyPrefixes lists the permitted read-only AWS SDK discovery prefixes.
var AllowedReadOnlyPrefixes = []string{
	"Describe",
	"Get",
	"List",
	"Lookup",
}

// Violation tracks an illegal mutating call or interface method.
type Violation struct {
	File       string
	Line       int
	MethodName string
	Prefix     string
	Context    string
}

// ScanFileForMutatingAWSCalls scans an AST file node for mutating AWS SDK calls or interface definitions.
func ScanFileForMutatingAWSCalls(fset *token.FileSet, node *ast.File, filePath string) []Violation {
	var violations []Violation

	// Check if file imports AWS SDK packages
	awsImportAliases := make(map[string]bool)
	hasAWSSDK := false
	for _, imp := range node.Imports {
		pathVal := strings.Trim(imp.Path.Value, `"`)
		if strings.HasPrefix(pathVal, "github.com/aws/aws-sdk-go-v2") {
			hasAWSSDK = true
			if imp.Name != nil {
				awsImportAliases[imp.Name.Name] = true
			} else {
				parts := strings.Split(pathVal, "/")
				pkgName := parts[len(parts)-1]
				awsImportAliases[pkgName] = true
			}
		}
	}

	ast.Inspect(node, func(n ast.Node) bool {
		switch x := n.(type) {
		// 1. Inspect interface declarations (e.g. EC2ClientAPI, S3BucketClientAPI)
		case *ast.TypeSpec:
			if iface, ok := x.Type.(*ast.InterfaceType); ok {
				for _, method := range iface.Methods.List {
					for _, name := range method.Names {
						for _, prefix := range ForbiddenMutatingPrefixes {
							if strings.HasPrefix(name.Name, prefix) {
								pos := fset.Position(name.Pos())
								violations = append(violations, Violation{
									File:       filePath,
									Line:       pos.Line,
									MethodName: name.Name,
									Prefix:     prefix,
									Context:    fmt.Sprintf("Interface %s defines mutating method %s", x.Name.Name, name.Name),
								})
							}
						}
					}
				}
			}

		// 2. Inspect method call expressions (e.g. client.CreateSecurityGroup, ec2.DeleteVolume)
		case *ast.CallExpr:
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
				methodName := sel.Sel.Name
				for _, prefix := range ForbiddenMutatingPrefixes {
					if strings.HasPrefix(methodName, prefix) {
						// Exclude internal non-AWS registry methods (e.g. r.Register(c ResourceCollector), engine.RegisterRules)
						if isInternalNonAWSCall(sel) {
							continue
						}

						// If the file imports AWS SDK or the receiver is an AWS client/package
						if hasAWSSDK || isAWSReceiver(sel, awsImportAliases) {
							pos := fset.Position(sel.Pos())
							violations = append(violations, Violation{
								File:       filePath,
								Line:       pos.Line,
								MethodName: methodName,
								Prefix:     prefix,
								Context:    fmt.Sprintf("Method call %s.%s violates read-only invariant", exprToString(sel.X), methodName),
							})
						}
					}
				}
			}
		}
		return true
	})

	return violations
}

func isInternalNonAWSCall(sel *ast.SelectorExpr) bool {
	methodName := sel.Sel.Name
	// Registry.Register for ResourceCollector registration
	if methodName == "Register" {
		recv := exprToString(sel.X)
		if recv == "r" || recv == "reg" || recv == "defaultRegistry" || recv == "collector" {
			return true
		}
	}
	// RulesEngine.RegisterRules
	if methodName == "RegisterRules" {
		return true
	}
	return false
}

func isAWSReceiver(sel *ast.SelectorExpr, awsAliases map[string]bool) bool {
	recv := exprToString(sel.X)
	if awsAliases[recv] {
		return true
	}
	lower := strings.ToLower(recv)
	return strings.Contains(lower, "client") ||
		strings.Contains(lower, "api") ||
		strings.Contains(lower, "ec2") ||
		strings.Contains(lower, "s3") ||
		strings.Contains(lower, "iam") ||
		strings.Contains(lower, "cloudcontrol") ||
		strings.Contains(lower, "dynamo") ||
		strings.Contains(lower, "sts") ||
		strings.Contains(lower, "org")
}

func exprToString(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return exprToString(e.X) + "." + e.Sel.Name
	default:
		return ""
	}
}

func findRepoRoot(t *testing.T) string {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("unable to locate repo root (containing go.mod) from %s", wd)
	return ""
}

// TestAdversarial_MechanicallyEnforcedReadOnlyGuarantee enforces that NO Go file
// in pkg/collector/... calls any forbidden mutating AWS SDK method.
func TestAdversarial_MechanicallyEnforcedReadOnlyGuarantee(t *testing.T) {
	repoRoot := findRepoRoot(t)
	collectorDir := filepath.Join(repoRoot, "pkg", "collector")

	fset := token.NewFileSet()
	var allViolations []Violation
	filesScanned := 0

	err := filepath.Walk(collectorDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}

		filesScanned++
		node, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return fmt.Errorf("failed to parse %s: %w", path, err)
		}

		violations := ScanFileForMutatingAWSCalls(fset, node, path)
		allViolations = append(allViolations, violations...)
		return nil
	})

	if err != nil {
		t.Fatalf("failed to walk pkg/collector: %v", err)
	}

	if filesScanned == 0 {
		t.Fatalf("expected to scan collector Go files, but found none in %s", collectorDir)
	}

	if len(allViolations) > 0 {
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("CRITICAL INVARIANT VIOLATION: Found %d mutating AWS SDK calls/definitions in pkg/collector:\n", len(allViolations)))
		for _, v := range allViolations {
			sb.WriteString(fmt.Sprintf("  - %s:%d: %s (prefix: %s) [%s]\n", v.File, v.Line, v.MethodName, v.Prefix, v.Context))
		}
		t.Fatal(sb.String())
	}

	t.Logf("Successfully scanned %d Go files in pkg/collector/... with ZERO forbidden mutating calls.", filesScanned)
}

// TestAdversarial_PkgWideReadOnlyGuarantee scans all packages in pkg/ (except pkg/reconcile)
// to verify the pervasive read-only invariant across the core codebase.
func TestAdversarial_PkgWideReadOnlyGuarantee(t *testing.T) {
	repoRoot := findRepoRoot(t)
	pkgDir := filepath.Join(repoRoot, "pkg")

	fset := token.NewFileSet()
	var allViolations []Violation
	filesScanned := 0

	err := filepath.Walk(pkgDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// Reconcile is explicitly exempt as it synthesizes remediation scripts
			if filepath.Base(path) == "reconcile" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		filesScanned++
		node, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return fmt.Errorf("failed to parse %s: %w", path, err)
		}

		violations := ScanFileForMutatingAWSCalls(fset, node, path)
		allViolations = append(allViolations, violations...)
		return nil
	})

	if err != nil {
		t.Fatalf("failed to walk pkg/: %v", err)
	}

	if len(allViolations) > 0 {
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("CRITICAL INVARIANT VIOLATION: Found %d mutating AWS SDK calls/definitions in pkg/:\n", len(allViolations)))
		for _, v := range allViolations {
			sb.WriteString(fmt.Sprintf("  - %s:%d: %s (prefix: %s) [%s]\n", v.File, v.Line, v.MethodName, v.Prefix, v.Context))
		}
		t.Fatal(sb.String())
	}

	t.Logf("Successfully verified pervasive read-only invariant across %d Go files in pkg/ (excluding reconcile).", filesScanned)
}

// TestAdversarial_ScannerDetectsForbiddenMutatingPrefixes verifies that the AST scanner
// rigorously detects every single forbidden mutating AWS SDK prefix when present.
func TestAdversarial_ScannerDetectsForbiddenMutatingPrefixes(t *testing.T) {
	for _, prefix := range ForbiddenMutatingPrefixes {
		testMethodName := prefix + "TargetResource"
		syntheticCode := fmt.Sprintf(`package testcollector
import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

type TestClientAPI interface {
	%s(ctx context.Context, input any) (any, error)
}

func DoMutation(client TestClientAPI) {
	client.%s(context.Background(), nil)
}
`, testMethodName, testMethodName)

		fset := token.NewFileSet()
		node, err := parser.ParseFile(fset, "synthetic_test.go", syntheticCode, 0)
		if err != nil {
			t.Fatalf("failed to parse synthetic test code for prefix %s: %v", prefix, err)
		}

		violations := ScanFileForMutatingAWSCalls(fset, node, "synthetic_test.go")
		if len(violations) == 0 {
			t.Fatalf("AST scanner failed to detect forbidden mutating prefix %q in synthetic code:\n%s", prefix, syntheticCode)
		}

		found := false
		for _, v := range violations {
			if v.Prefix == prefix && v.MethodName == testMethodName {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected violation for prefix %q and method %q, got: %+v", prefix, testMethodName, violations)
		}
	}
}

// TestAdversarial_ScannerPermitsAllowedReadOnlyPrefixes verifies that legitimate read-only
// discovery methods are correctly permitted by the AST scanner.
func TestAdversarial_ScannerPermitsAllowedReadOnlyPrefixes(t *testing.T) {
	for _, prefix := range AllowedReadOnlyPrefixes {
		testMethodName := prefix + "TargetResource"
		syntheticCode := fmt.Sprintf(`package testcollector
import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

type TestReadOnlyAPI interface {
	%s(ctx context.Context, input any) (any, error)
}

func DoDiscovery(client TestReadOnlyAPI) {
	client.%s(context.Background(), nil)
}
`, testMethodName, testMethodName)

		fset := token.NewFileSet()
		node, err := parser.ParseFile(fset, "synthetic_test.go", syntheticCode, 0)
		if err != nil {
			t.Fatalf("failed to parse synthetic test code for prefix %s: %v", prefix, err)
		}

		violations := ScanFileForMutatingAWSCalls(fset, node, "synthetic_test.go")
		if len(violations) > 0 {
			t.Fatalf("AST scanner falsely flagged allowed read-only prefix %q: %+v", prefix, violations)
		}
	}
}
