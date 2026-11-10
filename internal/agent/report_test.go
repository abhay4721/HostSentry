package agent

import (
	"testing"
	"time"
)

func TestEvaluatorRequiresSustainedThreshold(t *testing.T) {
	start := time.Date(2026, 11, 10, 10, 0, 0, 0, time.UTC)
	e := NewEvaluator()
	cfg := Thresholds{CPUPercent: 80, MemoryPercent: 90, DiskPercent: 90}
	report := Report{CPU: CPU{UsagePercent: 95}}
	if got := e.Evaluate(report, cfg, time.Minute, start); len(got) != 0 { t.Fatalf("alert fired before duration: %+v", got) }
	if got := e.Evaluate(report, cfg, time.Minute, start.Add(59*time.Second)); len(got) != 0 { t.Fatalf("alert fired early: %+v", got) }
	got := e.Evaluate(report, cfg, time.Minute, start.Add(time.Minute))
	if len(got) != 1 || got[0].Metric != "cpu" || got[0].Since != start { t.Fatalf("unexpected alerts: %+v", got) }
}

func TestEvaluatorClearsThresholdAfterRecovery(t *testing.T) {
	e := NewEvaluator()
	cfg := Thresholds{CPUPercent: 80}
	now := time.Now().UTC()
	e.Evaluate(Report{CPU: CPU{UsagePercent: 90}}, cfg, 0, now)
	if got := e.Evaluate(Report{CPU: CPU{UsagePercent: 70}}, cfg, 0, now.Add(time.Second)); len(got) != 0 { t.Fatalf("alert remained after recovery: %+v", got) }
	got := e.Evaluate(Report{CPU: CPU{UsagePercent: 91}}, cfg, 0, now.Add(2*time.Second))
	if len(got) != 1 || !got[0].Since.Equal(now.Add(2*time.Second)) { t.Fatalf("threshold state did not reset: %+v", got) }
}
