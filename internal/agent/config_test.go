package agent

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfigIsValid(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config invalid: %v", err)
	}
	if cfg.Interval.Value() != 30*time.Second || cfg.ProcessLimit != 20 {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	if cfg.Recovery.Enabled || !cfg.Recovery.DryRun {
		t.Fatalf("unsafe recovery defaults: enabled=%t dry_run=%t", cfg.Recovery.Enabled, cfg.Recovery.DryRun)
	}
}

func TestLoadConfigReadsDurationsAndThresholds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hostsentry.yaml")
	data := []byte("interval: 15s\nprocess_limit: 7\nsustain_for: 1m\nthresholds:\n  cpu_percent: 80\n  memory_percent: 85\n  disk_percent: 92\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Interval.Value() != 15*time.Second || cfg.SustainFor.Value() != time.Minute || cfg.ProcessLimit != 7 {
		t.Fatalf("config not applied: %+v", cfg)
	}
	if cfg.Thresholds.CPUPercent != 80 || cfg.Thresholds.MemoryPercent != 85 || cfg.Thresholds.DiskPercent != 92 {
		t.Fatalf("thresholds not applied: %+v", cfg.Thresholds)
	}
}

func TestRecoveryRemainsDryRunWhenConfigOmitsDryRun(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hostsentry.yaml")
	data := []byte(`services:
  - web.service
recovery:
  enabled: true
  audit_log: /tmp/hostsentry-recovery.jsonl
  policies:
    - name: web-restart
      enabled: true
      service: web.service
      failure_for: 30s
      max_attempts: 2
      cooldown: 5m
      verification_timeout: 30s
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Recovery.Enabled || !cfg.Recovery.DryRun {
		t.Fatalf("omitting dry_run must keep enabled recovery in dry-run: enabled=%t dry_run=%t", cfg.Recovery.Enabled, cfg.Recovery.DryRun)
	}
}

func TestLoadConfigRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hostsentry.yaml")
	if err := os.WriteFile(path, []byte("intervel: 5s\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected unknown field error")
	}
}

func TestConfigRejectsUnsafeValues(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ProcessLimit = 1001
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected process limit validation error")
	}
	cfg = DefaultConfig()
	cfg.Thresholds.DiskPercent = 101
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected disk threshold validation error")
	}
}
