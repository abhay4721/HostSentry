//go:build linux

package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

func TestCollectorReturnsLiveLinuxMetrics(t *testing.T) {
	report, err := NewCollector("test", 10).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.System.Hostname == "" {
		t.Fatal("hostname is empty")
	}
	if report.System.Architecture == "" {
		t.Fatal("architecture is empty")
	}
	if report.System.AgentVersion != "test" {
		t.Fatalf("agent version = %q", report.System.AgentVersion)
	}
	if report.Memory.TotalBytes == 0 {
		t.Fatal("memory total is zero")
	}
	if len(report.CPU.Cores) == 0 {
		t.Fatal("no CPU cores collected")
	}
	if len(report.Disks) == 0 {
		t.Fatal("no filesystems collected")
	}
	if report.CollectedAt.IsZero() {
		t.Fatal("collection time is empty")
	}
	if len(report.Processes) > 10 {
		t.Fatalf("process limit not honored: %d", len(report.Processes))
	}
}

func TestSystemdCollectorReadsServiceState(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	services, err := collectServices(ctx, []string{"systemd-journald.service"})
	if err != nil {
		connection, busErr := dbus.ConnectSystemBus()
		if busErr != nil {
			t.Skipf("system D-Bus is unavailable in this test environment: %v", busErr)
		}
		_ = connection.Close()
		t.Fatalf("collect systemd-journald.service: %v", err)
	}
	if len(services) != 1 || services[0].Name != "systemd-journald.service" {
		t.Fatalf("unexpected service results: %+v", services)
	}
	if services[0].LoadState == "" || services[0].ActiveState == "" || services[0].SubState == "" {
		t.Fatalf("service state is incomplete: %+v", services[0])
	}
}

func TestCalculateNetworkRates(t *testing.T) {
	c := &Collector{}
	start := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	first := c.calculateNetworkRates([]NetCounters{{Name: "eth0", RXBytes: 100, TXBytes: 200}}, start)
	if first[0].RXBytesPerSecond != 0 || first[0].TXBytesPerSecond != 0 {
		t.Fatal("first network sample must not invent a rate")
	}
	second := c.calculateNetworkRates([]NetCounters{{Name: "eth0", RXBytes: 1100, TXBytes: 2200}}, start.Add(2*time.Second))
	if second[0].RXBytesPerSecond != 500 || second[0].TXBytesPerSecond != 1000 {
		t.Fatalf("rates = %.0f/%.0f, want 500/1000", second[0].RXBytesPerSecond, second[0].TXBytesPerSecond)
	}
	reset := c.calculateNetworkRates([]NetCounters{{Name: "eth0", RXBytes: 5, TXBytes: 8}}, start.Add(4*time.Second))
	if reset[0].RXBytesPerSecond != 0 || reset[0].TXBytesPerSecond != 0 {
		t.Fatal("counter reset must not produce negative or fabricated throughput")
	}
}

func TestGenerateRecommendationsIsReadOnly(t *testing.T) {
	report := Report{Disks: []Disk{{Mountpoint: "/var", UsagePercent: 85}, {Mountpoint: "/boot", ReadOnly: true}}, Services: []ServiceState{{Name: "web.service", ActiveState: "failed"}}, Processes: []Process{{PID: 123, Name: "worker", CPUPercent: 70}}}
	recommendations := generateRecommendations(report)
	if len(recommendations) != 4 {
		t.Fatalf("got %d recommendations, want 4: %+v", len(recommendations), recommendations)
	}
	for _, item := range recommendations {
		if item.Type == "disk_cleanup_review" && !strings.Contains(item.Message, "will not delete files automatically") {
			t.Fatalf("disk recommendation lacks its non-destructive boundary: %+v", item)
		}
		if item.Type == "process_diagnostics" && !strings.Contains(item.Message, "will not terminate processes automatically") {
			t.Fatalf("process recommendation lacks its non-destructive boundary: %+v", item)
		}
	}
}
