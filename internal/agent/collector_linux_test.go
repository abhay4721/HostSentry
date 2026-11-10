//go:build linux

package agent

import (
	"context"
	"testing"
)

func TestCollectorReturnsLiveLinuxMetrics(t *testing.T) {
	report, err := NewCollector("test", 10).Collect(context.Background())
	if err != nil { t.Fatal(err) }
	if report.System.Hostname == "" { t.Fatal("hostname is empty") }
	if report.System.Architecture == "" { t.Fatal("architecture is empty") }
	if report.System.AgentVersion != "test" { t.Fatalf("agent version = %q", report.System.AgentVersion) }
	if report.Memory.TotalBytes == 0 { t.Fatal("memory total is zero") }
	if len(report.CPU.Cores) == 0 { t.Fatal("no CPU cores collected") }
	if len(report.Disks) == 0 { t.Fatal("no filesystems collected") }
	if report.CollectedAt.IsZero() { t.Fatal("collection time is empty") }
	if len(report.Processes) > 10 { t.Fatalf("process limit not honored: %d", len(report.Processes)) }
}
