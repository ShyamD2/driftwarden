package models

import "time"

// ResourceSource indicates the origin plane of a resource definition.
type ResourceSource string

const (
	SourceDesired ResourceSource = "DESIRED"
	SourceState   ResourceSource = "STATE"
	SourceLive    ResourceSource = "LIVE"
)

// ResourceAvailability represents whether a resource was successfully confirmed present, absent, or unreachable.
type ResourceAvailability string

const (
	AvailabilityPresent     ResourceAvailability = "PRESENT"
	AvailabilityAbsent      ResourceAvailability = "ABSENT"
	AvailabilityUnknown     ResourceAvailability = "UNKNOWN"
	AvailabilityUnavailable ResourceAvailability = "UNAVAILABLE" // AccessDenied or permission boundary
	AvailabilityUnsupported ResourceAvailability = "UNSUPPORTED"
)

// AttributeValueKind classifies how an attribute value is expressed in configuration.
type AttributeValueKind string

const (
	AttributeLiteral    AttributeValueKind = "LITERAL"
	AttributeExpression AttributeValueKind = "EXPRESSION"
	AttributeReference  AttributeValueKind = "REFERENCE"
	AttributeUnknown    AttributeValueKind = "UNKNOWN"
)

// DriftType classifies the divergence between Desired, State, and Live planes.
type DriftType string

const (
	DriftInSync          DriftType = "IN_SYNC"
	DriftAttribute       DriftType = "ATTRIBUTE_DRIFT"
	DriftShadow          DriftType = "SHADOW_RESOURCE"
	DriftGhost           DriftType = "GHOST_RESOURCE"
	DriftUnappliedConfig DriftType = "UNAPPLIED_CONFIG_DRIFT"
	DriftSplitBrain      DriftType = "SPLIT_BRAIN_DRIFT"
)

// Severity represents the impact or criticality level of a drift or security item.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// CollectorCapabilities defines what capabilities a resource collector supports.
// Forward-compatible contract schema for Phase 1.
type CollectorCapabilities struct {
	Discover        bool `json:"discover"`
	Normalize       bool `json:"normalize"`
	Compare         bool `json:"compare"`
	SecurityAnalyze bool `json:"security_analyze"`
	CostEstimate    bool `json:"cost_estimate"`
	Reconcile       bool `json:"reconcile"`
}

// CanonicalResource represents a standardized, source-attributed cloud resource.
type CanonicalResource struct {
	CanonicalID        string               `json:"canonical_id"` // aws:<partition>:<service>:<region>:<account>:<type>/<id>
	Type               string               `json:"type"`         // e.g. aws_security_group
	ProviderID         string               `json:"provider_id"`  // e.g. sg-0123456789
	Name               string               `json:"name"`
	AccountID          string               `json:"account_id"`
	Region             string               `json:"region"`
	Attributes         map[string]any       `json:"attributes"`
	Tags               map[string]string    `json:"tags"`
	Source             ResourceSource       `json:"source"`
	Availability       ResourceAvailability `json:"availability"`
	IsDefault          bool                 `json:"is_default"`
	IdentityConfidence float64              `json:"identity_confidence"` // 0.0 to 1.0
	IdentityEvidence   []string             `json:"identity_evidence"`
}

// CostEstimate represents financial impact data.
// Forward-compatible contract schema for Phase 1.
type CostEstimate struct {
	AmountMonthly float64   `json:"amount_monthly"`
	Currency      string    `json:"currency"`
	Region        string    `json:"region"`
	PricingSource string    `json:"pricing_source"`
	PricingModel  string    `json:"pricing_model"`
	RetrievedAt   time.Time `json:"retrieved_at"`
	Confidence    float64   `json:"confidence"`
}

// DiffDetail represents field-level discrepancy across planes.
type DiffDetail struct {
	DesiredValue     any                `json:"desired_value,omitempty"`
	StateValue       any                `json:"state_value,omitempty"`
	LiveValue        any                `json:"live_value,omitempty"`
	AttributeKind    AttributeValueKind `json:"attribute_kind"`
	ResolutionStatus string             `json:"resolution_status,omitempty"` // e.g. UNRESOLVED_DESIRED_VALUE
}

// DriftItem encapsulates a single detected divergence or finding.
type DriftItem struct {
	Resource           CanonicalResource     `json:"resource"`
	Type               DriftType             `json:"drift_type"`
	Severity           Severity              `json:"severity"`
	Diffs              map[string]DiffDetail `json:"diffs"`
	DoubleReadVerified bool                  `json:"double_read_verified"`
	FindingConfidence  float64               `json:"finding_confidence"` // 0.0 to 1.0
	FindingEvidence    []string              `json:"finding_evidence"`
	CISRuleID          string                `json:"cis_rule_id,omitempty"`
	Cost               *CostEstimate         `json:"cost,omitempty"`
	Capabilities       CollectorCapabilities `json:"capabilities"`
}

// APIEfficiency tracks cloud provider call counts, retries, and efficiency ratios.
type APIEfficiency struct {
	TotalAPICalls    int64            `json:"total_api_calls"`
	Retries          int64            `json:"retries"`
	Throttles        int64            `json:"throttles"`
	CallsPerRegion   map[string]int64 `json:"calls_per_region,omitempty"`
	CallsPerService  map[string]int64 `json:"calls_per_service,omitempty"`
	CallsPerResource float64          `json:"calls_per_resource"`
}

// ScanReport is the top-level report emitted by audit and scan commands.
type ScanReport struct {
	ReportSchemaVersion string            `json:"schema_version"` // "1.0.0"
	ToolVersion         string            `json:"tool_version"`
	ScanID              string            `json:"scan_id"`
	Timestamp           string            `json:"timestamp"`
	AccountID           string            `json:"account_id"`
	Regions             []string          `json:"regions"`
	SnapshotMode        string            `json:"snapshot_mode"` // "CURRENT", "HISTORICAL_SNAPSHOT (STALE)"
	Status              string            `json:"status"`        // "COMPLETE", "PARTIAL_SCAN", "FAILED"
	TotalScanned        int               `json:"total_scanned"`
	TotalDrift          int               `json:"total_drift"`
	AccessDeniedCount   int               `json:"access_denied_count"`
	Items               []DriftItem       `json:"items"`
	Summary             map[DriftType]int `json:"summary"`
	ExecutionTimeMs     int64             `json:"execution_time_ms"`
	APIEfficiency       *APIEfficiency    `json:"api_efficiency,omitempty"`
}
