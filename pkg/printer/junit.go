package printer

import (
	"encoding/xml"
	"fmt"
	"io"

	"github.com/ShyamD2/driftwarden/pkg/models"
)

type jUnitTestSuites struct {
	XMLName  xml.Name         `xml:"testsuites"`
	Name     string           `xml:"name,attr"`
	Tests    int              `xml:"tests,attr"`
	Failures int              `xml:"failures,attr"`
	Time     string           `xml:"time,attr"`
	Suites   []jUnitTestSuite `xml:"testsuite"`
}

type jUnitTestSuite struct {
	XMLName   xml.Name        `xml:"testsuite"`
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	Errors    int             `xml:"errors,attr"`
	Time      string          `xml:"time,attr"`
	TestCases []jUnitTestCase `xml:"testcase"`
}

type jUnitTestCase struct {
	XMLName   xml.Name      `xml:"testcase"`
	ClassName string        `xml:"classname,attr"`
	Name      string        `xml:"name,attr"`
	Time      string        `xml:"time,attr"`
	Failure   *jUnitFailure `xml:"failure,omitempty"`
}

type jUnitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Content string `xml:",chardata"`
}

// PrintJUnit renders a ScanReport as JUnit XML format suitable for CI/CD test runners.
func PrintJUnit(w io.Writer, report *models.ScanReport) error {
	if report == nil {
		return fmt.Errorf("report is nil")
	}

	timeSec := fmt.Sprintf("%.3f", float64(report.ExecutionTimeMs)/1000.0)
	var testCases []jUnitTestCase

	failuresCount := 0
	for _, item := range report.Items {
		tc := jUnitTestCase{
			ClassName: item.Resource.Type,
			Name:      item.Resource.CanonicalID,
			Time:      "0.001",
		}

		if item.Type != models.DriftInSync {
			failuresCount++
			msg := fmt.Sprintf("Divergence detected: %s (Severity: %s)", item.Type, item.Severity)
			content := fmt.Sprintf("Canonical ID: %s\nDrift Type: %s\nSeverity: %s\nConfidence: %.2f\nCIS Rule: %s\n",
				item.Resource.CanonicalID, item.Type, item.Severity, item.FindingConfidence, item.CISRuleID)
			if len(item.FindingEvidence) > 0 {
				content += fmt.Sprintf("Evidence: %v\n", item.FindingEvidence)
			}

			tc.Failure = &jUnitFailure{
				Message: msg,
				Type:    string(item.Type),
				Content: content,
			}
		}

		testCases = append(testCases, tc)
	}

	totalTests := len(testCases)
	if totalTests == 0 {
		totalTests = report.TotalScanned
		// Add a passing dummy testcase if no items
		testCases = append(testCases, jUnitTestCase{
			ClassName: "Infrastructure",
			Name:      "CloudResourceAudit",
			Time:      timeSec,
		})
	}

	suite := jUnitTestSuite{
		Name:      "Infrastructure Drift & Security Audit",
		Tests:     totalTests,
		Failures:  failuresCount,
		Errors:    0,
		Time:      timeSec,
		TestCases: testCases,
	}

	suites := jUnitTestSuites{
		Name:     "DriftWarden",
		Tests:    totalTests,
		Failures: failuresCount,
		Time:     timeSec,
		Suites:   []jUnitTestSuite{suite},
	}

	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(suites); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}
