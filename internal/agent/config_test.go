package agent

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfigIsValid(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil { t.Fatalf("default config invalid: %v", err) }
	if cfg.Interval.Value() != 30*time.Second || cfg.ProcessLimit != 20 { t.Fatalf("unexpected defaults: %+v", cfg) }
}

func TestLoadConfigReadsDurationsAndThresholds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hostsentry.yaml")
	data := []byte("interval: 15s\nprocess_limit: 7\nsustain_for: 1m\nthresholds:\n  cpu_percent: 80\n  memory_percent: 85\n  disk_percent: 92\n")
	if err := os.WriteFile(path, data, 0o600); err != nil { t.Fatal(err) }
	cfg, err := LoadConfig(path)
	if err != nil { t.Fatal(err) }
	if cfg.Interval.Value() != 15*time.Second || cfg.SustainFor.Value() != time.Minute || cfg.ProcessLimit != 7 { t.Fatalf("config not applied: %+v", cfg) }
	if cfg.Thresholds.CPUPercent != 80 || cfg.Thresholds.MemoryPercent != 85 || cfg.Thresholds.DiskPercent != 92 { t.Fatalf("thresholds not applied: %+v", cfg.Thresholds) }
}

func TestLoadConfigRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hostsentry.yaml")
	if err := os.WriteFile(path, []byte("intervel: 5s\n"), 0o600); err != nil { t.Fatal(err) }
	if _, err := LoadConfig(path); err == nil { t.Fatal("expected unknown field error") }
}

func TestConfigRejectsUnsafeValues(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ProcessLimit = 1001
	if err := cfg.Validate(); err == nil { t.Fatal("expected process limit validation error") }
	cfg = DefaultConfig()
	cfg.Thresholds.DiskPercent = 101
	if err := cfg.Validate(); err == nil { t.Fatal("expected disk threshold validation error") }
}
