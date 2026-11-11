package agent

import (
	"strings"
	"testing"
	"time"
)

func TestReportQueuePreservesRecoveryWhenTrimmingSnapshots(t *testing.T) {
	queue := NewReportQueue(t.TempDir()+"/queue.jsonl", 2000)
	started := time.Date(2026, 11, 10, 10, 0, 0, 0, time.UTC)
	first := Report{CollectedAt: started, Recoveries: []RecoveryExecution{{
		Policy: "restart", Service: "example.service", StartedAt: started,
		FinishedAt: started.Add(time.Second), Outcome: "succeeded", Verified: true,
	}}}
	for _, item := range []queuedReport{
		{ID: "first", Report: first},
		{ID: "second", Report: Report{CollectedAt: started.Add(time.Minute), Warnings: []string{strings.Repeat("s", 900)}}},
		{ID: "third", Report: Report{CollectedAt: started.Add(2 * time.Minute), Warnings: []string{strings.Repeat("t", 900)}}},
	} {
		if err := queue.Push(item); err != nil {
			t.Fatalf("push %s: %v", item.ID, err)
		}
	}

	item, ok, err := queue.Peek()
	if err != nil || !ok {
		t.Fatalf("peek retained report: ok=%v err=%v", ok, err)
	}
	if item.ID != "third" {
		t.Fatalf("retained report id = %q, want latest snapshot", item.ID)
	}
	if len(item.Report.Recoveries) != 1 || item.Report.Recoveries[0].Policy != "restart" {
		t.Fatalf("pending recovery was lost while trimming: %+v", item.Report.Recoveries)
	}
}

func TestReportQueueRefusesToDropRecoveryWhenHistoryCannotFit(t *testing.T) {
	queue := NewReportQueue(t.TempDir()+"/queue.jsonl", 1024)
	started := time.Now().UTC()
	item := queuedReport{ID: "one", Report: Report{CollectedAt: started, Recoveries: []RecoveryExecution{{
		Policy: "restart", Service: "example.service", StartedAt: started,
		FinishedAt: started.Add(time.Second), Outcome: "succeeded", Verified: true,
	}}}}
	if err := queue.Push(item); err != nil {
		t.Fatalf("push initial report: %v", err)
	}
	// A single report with a growing recovery history must fail without replacing
	// the previous durable queue contents.
	tooLarge := item
	tooLarge.ID = "two"
	tooLarge.Report.Recoveries = make([]RecoveryExecution, 0, 20)
	for i := 0; i < 20; i++ {
		recovery := item.Report.Recoveries[0]
		recovery.Policy = strings.Repeat("policy", 10) + string(rune('a'+i))
		tooLarge.Report.Recoveries = append(tooLarge.Report.Recoveries, recovery)
	}
	if err := queue.Push(tooLarge); err == nil {
		t.Fatal("expected oversized recovery report to be rejected")
	}
	retained, ok, err := queue.Peek()
	if err != nil || !ok || retained.ID != "one" || len(retained.Report.Recoveries) != 1 {
		t.Fatalf("previous queue contents changed after rejection: item=%+v ok=%v err=%v", retained, ok, err)
	}
}
