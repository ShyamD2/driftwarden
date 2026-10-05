package rules

import (
	"github.com/ShyamD2/driftwarden/pkg/analyzer"
	v3 "github.com/ShyamD2/driftwarden/pkg/rules/cis/v3"
)

// RegisterDefaultRules registers all standard CIS v3 and governance rules into an engine.
func RegisterDefaultRules(engine *analyzer.SecurityEngine) {
	if engine == nil {
		return
	}
	engine.RegisterRules(
		v3.NewDWCIS_EC2_001(),
		v3.NewDWCIS_EC2_002(),
		v3.NewDWCIS_S3_001(),
		v3.NewDWCIS_S3_002(),
		v3.NewDWCIS_IAM_001(),
		v3.NewDWGOV_TAG_001(),
	)
}

// NewDefaultEngine creates and returns a SecurityEngine pre-populated with standard rules.
func NewDefaultEngine() *analyzer.SecurityEngine {
	engine := analyzer.NewSecurityEngine()
	RegisterDefaultRules(engine)
	return engine
}
