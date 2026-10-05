package printer

import (
	"fmt"
	"io"
	"strings"

	"github.com/olekukonko/tablewriter"

	"github.com/ShyamD2/driftwarden/pkg/models"
)

// PrintExplainDossier renders a comprehensive diagnostic dossier for a specific resource.
func PrintExplainDossier(w io.Writer, targetID string, report *models.ScanReport, resources []models.CanonicalResource) error {
	var item *models.DriftItem
	var res *models.CanonicalResource

	// Search in drift items
	if report != nil {
		for i := range report.Items {
			if report.Items[i].Resource.CanonicalID == targetID || report.Items[i].Resource.ProviderID == targetID {
				item = &report.Items[i]
				res = &item.Resource
				break
			}
		}
	}

	// Search in all resources if not found in drift items
	if res == nil {
		for i := range resources {
			if resources[i].CanonicalID == targetID || resources[i].ProviderID == targetID {
				res = &resources[i]
				break
			}
		}
	}

	if res == nil {
		return fmt.Errorf("resource '%s' not found in scan inventory or drift findings", targetID)
	}

	fmt.Fprintf(w, "\n========================================================================================\n")
	fmt.Fprintf(w, "  DRIFTWARDEN DIAGNOSTIC DOSSIER\n")
	fmt.Fprintf(w, "========================================================================================\n")
	fmt.Fprintf(w, "Canonical ID:        %s\n", res.CanonicalID)
	fmt.Fprintf(w, "Resource Type:       %s\n", res.Type)
	fmt.Fprintf(w, "Provider ID:         %s\n", res.ProviderID)
	fmt.Fprintf(w, "Account ID:          %s\n", res.AccountID)
	fmt.Fprintf(w, "Region:              %s\n", res.Region)
	fmt.Fprintf(w, "Source Plane:        %s\n", res.Source)
	fmt.Fprintf(w, "Availability:        %s\n", res.Availability)
	fmt.Fprintf(w, "Identity Confidence: %.2f\n", res.IdentityConfidence)

	if item != nil {
		fmt.Fprintf(w, "Finding Confidence:  %.2f\n", item.FindingConfidence)
		verifiedStr := "NO"
		if item.DoubleReadVerified {
			verifiedStr = "VERIFIED (Double-Read Confirmed)"
		}
		fmt.Fprintf(w, "Double-Read Probe:   %s\n", verifiedStr)

		fmt.Fprintf(w, "\n----------------------------------------------------------------------------------------\n")
		fmt.Fprintf(w, "DRIFT CLASSIFICATION\n")
		fmt.Fprintf(w, "----------------------------------------------------------------------------------------\n")
		fmt.Fprintf(w, "Drift Type:          %s\n", item.Type)
		fmt.Fprintf(w, "Severity:            %s\n", item.Severity)
		if len(item.FindingEvidence) > 0 {
			fmt.Fprintf(w, "Evidence Trail:\n")
			for _, ev := range item.FindingEvidence {
				fmt.Fprintf(w, "  • %s\n", ev)
			}
		}

		if item.Cost != nil {
			fmt.Fprintf(w, "\n----------------------------------------------------------------------------------------\n")
			fmt.Fprintf(w, "FINANCIAL IMPACT (COST ANALYSIS)\n")
			fmt.Fprintf(w, "----------------------------------------------------------------------------------------\n")
			fmt.Fprintf(w, "Estimated Monthly Waste: $%.2f %s\n", item.Cost.AmountMonthly, item.Cost.Currency)
			fmt.Fprintf(w, "Pricing Model:           %s\n", item.Cost.PricingModel)
			fmt.Fprintf(w, "Pricing Source:          %s\n", item.Cost.PricingSource)
		}

		if item.CISRuleID != "" {
			fmt.Fprintf(w, "\n----------------------------------------------------------------------------------------\n")
			fmt.Fprintf(w, "SECURITY & COMPLIANCE POSTURE\n")
			fmt.Fprintf(w, "----------------------------------------------------------------------------------------\n")
			fmt.Fprintf(w, "CIS Rule ID:         %s\n", item.CISRuleID)
			fmt.Fprintf(w, "Severity:            %s\n", item.Severity)
		}

		fmt.Fprintf(w, "\n----------------------------------------------------------------------------------------\n")
		fmt.Fprintf(w, "ATTRIBUTE DIVERGENCE MATRIX (DESIRED ↔ STATE ↔ LIVE)\n")
		fmt.Fprintf(w, "----------------------------------------------------------------------------------------\n")
		if len(item.Diffs) == 0 {
			fmt.Fprintf(w, "No individual attribute divergences recorded.\n")
		} else {
			table := tablewriter.NewWriter(w)
			table.SetHeader([]string{"Attribute", "Desired (HCL)", "State (tfstate)", "Live (AWS)", "Kind", "Status"})
			table.SetBorder(true)
			table.SetAutoWrapText(false)

			for attr, diff := range item.Diffs {
				dStr := fmtValue(diff.DesiredValue)
				sStr := fmtValue(diff.StateValue)
				lStr := fmtValue(diff.LiveValue)
				status := diff.ResolutionStatus
				if status == "" {
					status = "DIFF"
				}
				table.Append([]string{
					attr,
					truncateString(dStr, 25),
					truncateString(sStr, 25),
					truncateString(lStr, 25),
					string(diff.AttributeKind),
					status,
				})
			}
			table.Render()
		}
	} else {
		fmt.Fprintf(w, "\n----------------------------------------------------------------------------------------\n")
		fmt.Fprintf(w, "DRIFT CLASSIFICATION\n")
		fmt.Fprintf(w, "----------------------------------------------------------------------------------------\n")
		fmt.Fprintf(w, "Status:              IN_SYNC (Zero divergence detected)\n")
	}

	fmt.Fprintf(w, "========================================================================================\n\n")
	return nil
}

func fmtValue(v any) string {
	if v == nil {
		return "-"
	}
	s := fmt.Sprintf("%v", v)
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}
