package config

import (
	"time"

	"github.com/spf13/viper"
	"golang.org/x/time/rate"
)

// Config holds decoupled configuration parameters populated from CLI flags or configuration sources.
// Core engines consume this struct rather than interacting directly with Cobra or Viper.
type Config struct {
	Regions                 []string
	Profile                 string
	RoleARN                 string
	ExternalID              string
	LogLevel                string
	LogFormat               string
	NoColor                 bool
	Timeout                 time.Duration
	Concurrency             int
	RateLimit               int
	LocalStackEndpoint      string
	TFStatePath             string
	HCLDir                  string
	BackendS3Glob           string
	DynamoDBTable           string
	S3VersionID             string
	AllowHistoricalSnapshot bool
	WaitForLock             time.Duration
	VerifyConsistencyDelay  time.Duration
	Format                  string
	Output                  string
	FailOnDrift             bool
	FailOnCritical          bool
	IncludeSystemDefaults   bool
	IncludeLowConfidence    bool
	Organization            bool
	OrgRoleName             string
	CostRegion              string
	NoCost                  bool
	SaveEvidenceDir         string
	FromScanDir             string
}

// NewDefaultConfig initializes a Config struct populated with the exact default values
// defined in the DriftWarden CLI specification.
func NewDefaultConfig() *Config {
	return &Config{
		Regions:                 []string{"us-east-1"},
		Profile:                 "",
		RoleARN:                 "",
		ExternalID:              "",
		LogLevel:                "info",
		LogFormat:               "text",
		NoColor:                 false,
		Timeout:                 60 * time.Second,
		Concurrency:             8,
		RateLimit:               15,
		LocalStackEndpoint:      "",
		TFStatePath:             "terraform.tfstate",
		HCLDir:                  ".",
		BackendS3Glob:           "",
		DynamoDBTable:           "",
		S3VersionID:             "",
		AllowHistoricalSnapshot: false,
		WaitForLock:             0,
		VerifyConsistencyDelay:  2500 * time.Millisecond,
		Format:                  "table",
		Output:                  "",
		FailOnDrift:             false,
		FailOnCritical:          false,
		IncludeSystemDefaults:   false,
		IncludeLowConfidence:    false,
		Organization:            false,
		OrgRoleName:             "DriftWardenExecutionRole",
		CostRegion:              "us-east-1",
		NoCost:                  false,
		SaveEvidenceDir:         "",
		FromScanDir:             "",
	}
}

// NewRateLimiter creates a token bucket rate limiter configured with the rate limit from Config.
func (c *Config) NewRateLimiter() *rate.Limiter {
	limit := rate.Limit(c.RateLimit)
	if limit <= 0 {
		limit = rate.Limit(15)
	}
	return rate.NewLimiter(limit, int(limit))
}

// LoadFromViper populates Config from a Viper instance, decoupling configuration sources from business engines.
func LoadFromViper(v *viper.Viper, cfg *Config) {
	if v == nil || cfg == nil {
		return
	}
	if v.IsSet("regions") {
		cfg.Regions = v.GetStringSlice("regions")
	}
	if v.IsSet("profile") {
		cfg.Profile = v.GetString("profile")
	}
	if v.IsSet("role-arn") {
		cfg.RoleARN = v.GetString("role-arn")
	}
	if v.IsSet("external-id") {
		cfg.ExternalID = v.GetString("external-id")
	}
	if v.IsSet("log-level") {
		cfg.LogLevel = v.GetString("log-level")
	}
	if v.IsSet("log-format") {
		cfg.LogFormat = v.GetString("log-format")
	}
	if v.IsSet("no-color") {
		cfg.NoColor = v.GetBool("no-color")
	}
	if v.IsSet("timeout") {
		cfg.Timeout = v.GetDuration("timeout")
	}
	if v.IsSet("concurrency") {
		cfg.Concurrency = v.GetInt("concurrency")
	}
	if v.IsSet("rate-limit") {
		cfg.RateLimit = v.GetInt("rate-limit")
	}
	if v.IsSet("localstack-endpoint") {
		cfg.LocalStackEndpoint = v.GetString("localstack-endpoint")
	}
	if v.IsSet("tfstate") {
		cfg.TFStatePath = v.GetString("tfstate")
	}
	if v.IsSet("hcl-dir") {
		cfg.HCLDir = v.GetString("hcl-dir")
	}
}
