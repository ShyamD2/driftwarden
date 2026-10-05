package config

import (
	"reflect"
	"testing"
	"time"
)

func TestNewDefaultConfig(t *testing.T) {
	cfg := NewDefaultConfig()
	if cfg == nil {
		t.Fatal("expected non-nil default config")
	}

	if !reflect.DeepEqual(cfg.Regions, []string{"us-east-1"}) {
		t.Errorf("expected default regions [us-east-1], got %v", cfg.Regions)
	}
	if cfg.Timeout != 60*time.Second {
		t.Errorf("expected timeout 60s, got %v", cfg.Timeout)
	}
	if cfg.Concurrency != 8 {
		t.Errorf("expected concurrency 8, got %d", cfg.Concurrency)
	}
	if cfg.RateLimit != 15 {
		t.Errorf("expected rate limit 15, got %d", cfg.RateLimit)
	}
	if cfg.TFStatePath != "terraform.tfstate" {
		t.Errorf("expected TFStatePath terraform.tfstate, got %s", cfg.TFStatePath)
	}
	if cfg.HCLDir != "." {
		t.Errorf("expected HCLDir ., got %s", cfg.HCLDir)
	}
	if cfg.VerifyConsistencyDelay != 2500*time.Millisecond {
		t.Errorf("expected VerifyConsistencyDelay 2.5s, got %v", cfg.VerifyConsistencyDelay)
	}
	if cfg.Format != "table" {
		t.Errorf("expected Format table, got %s", cfg.Format)
	}
	if cfg.CostRegion != "us-east-1" {
		t.Errorf("expected CostRegion us-east-1, got %s", cfg.CostRegion)
	}
	if cfg.OrgRoleName != "DriftWardenExecutionRole" {
		t.Errorf("expected OrgRoleName DriftWardenExecutionRole, got %s", cfg.OrgRoleName)
	}
}
