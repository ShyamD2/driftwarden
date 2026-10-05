package printer

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/ShyamD2/driftwarden/pkg/models"
)

// PrintJSON serializes a ScanReport as indented JSON adhering to schema version 1.0.0.
func PrintJSON(w io.Writer, report *models.ScanReport) error {
	if report == nil {
		return fmt.Errorf("report is nil")
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
