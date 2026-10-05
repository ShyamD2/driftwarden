package printer

import (
	"fmt"
	"io"
	"strings"

	"github.com/olekukonko/tablewriter"

	"github.com/ShyamD2/driftwarden/pkg/models"
)

// PrintTable formats and renders a ScanReport as a clean terminal table.
func PrintTable(w io.Writer, report *models.ScanReport, noColor bool) error {
	if report == nil {
		return fmt.Errorf("report is nil")
	}

	fmt.Fprintf(w, "\n========================================================================================\n")
	fmt.Fprintf(w, "  DRIFTWARDEN INFRASTRUCTURE SCAN REPORT\n")
	fmt.Fprintf(w, "========================================================================================\n")
	fmt.Fprintf(w, "Scan ID:          %s\n", report.ScanID)
	fmt.Fprintf(w, "Timestamp:        %s\n", report.Timestamp)
	fmt.Fprintf(w, "Account ID:       %s\n", report.AccountID)
	fmt.Fprintf(w, "Regions:          %s\n", strings.Join(report.Regions, ", "))
	fmt.Fprintf(w, "Audit Status:     %s\n", report.Status)
	fmt.Fprintf(w, "Total Scanned:    %d\n", report.TotalScanned)
	fmt.Fprintf(w, "Total Drift:      %d\n", report.TotalDrift)
	if report.AccessDeniedCount > 0 {
		fmt.Fprintf(w, "Access Denied:    %d (PARTIAL_SCAN)\n", report.AccessDeniedCount)
	}
	fmt.Fprintf(w, "Execution Time:   %d ms\n", report.ExecutionTimeMs)
	fmt.Fprintf(w, "----------------------------------------------------------------------------------------\n\n")

	if len(report.Items) == 0 {
		fmt.Fprintf(w, "✓ Infrastructure is in sync with state and security policy. Zero drift detected.\n\n")
		return nil
	}

	table := tablewriter.NewWriter(w)
	table.SetHeader([]string{"Canonical ID", "Type", "Drift Type", "Severity", "Confidence", "CIS Rule", "Monthly Waste"})
	table.SetBorder(true)
	table.SetAutoWrapText(false)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)

	for _, item := range report.Items {
		costStr := "-"
		if item.Cost != nil {
			costStr = fmt.Sprintf("$%.2f", item.Cost.AmountMonthly)
		}
		cisRule := "-"
		if item.CISRuleID != "" {
			cisRule = item.CISRuleID
		}

		confStr := fmt.Sprintf("%.2f", item.FindingConfidence)

		table.Append([]string{
			truncateString(item.Resource.CanonicalID, 45),
			item.Resource.Type,
			string(item.Type),
			string(item.Severity),
			confStr,
			cisRule,
			costStr,
		})
	}

	table.Render()
	fmt.Fprintf(w, "\n")

	return nil
}

func truncateString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}
