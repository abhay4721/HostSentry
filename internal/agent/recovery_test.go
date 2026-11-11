package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRecoveryDryRunPersistsCooldownAndAudit(t *testing.T) {
	dir := t.TempDir()
	audit := filepath.Join(dir, "recovery.jsonl")
	now := time.Now().UTC()
	cfg := RecoveryConfig{Enabled: true, DryRun: true, AuditLog: audit, Policies: []RecoveryPolicy{{Name: "web", Enabled: true, Service: "web.service", FailureFor: Duration(0), MaxAttempts: 2, Cooldown: Duration(5 * time.Minute), VerificationTimeout: Duration(time.Second)}}}
	engine := NewRecoveryEngine(audit)
	runs, warnings := engine.Evaluate(context.Background(), []ServiceState{{Name: "web.service", ActiveState: "failed"}}, cfg, now)
	if len(warnings) != 0 || len(runs) != 1 || runs[0].Outcome != "dry_run" {
		t.Fatalf("dry-run result=%+v warnings=%v", runs, warnings)
	}
	info, err := os.Stat(audit)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("audit mode=%o", info.Mode().Perm())
	}
	stateInfo, err := os.Stat(audit + ".state")
	if err != nil {
		t.Fatal(err)
	}
	if stateInfo.Mode().Perm() != 0o600 {
		t.Fatalf("state mode=%o", stateInfo.Mode().Perm())
	}
	engine = NewRecoveryEngine(audit)
	runs, _ = engine.Evaluate(context.Background(), []ServiceState{{Name: "web.service", ActiveState: "failed"}}, cfg, now.Add(time.Minute))
	if len(runs) != 0 {
		t.Fatalf("cooldown did not persist after restart: %+v", runs)
	}
	contents, err := os.ReadFile(audit)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(contents), "dry_run") != 1 {
		t.Fatalf("unexpected audit contents %q", contents)
	}
}

func TestCorruptRecoveryStateFailsClosed(t *testing.T) {
	audit := filepath.Join(t.TempDir(), "recovery.jsonl")
	if err := os.WriteFile(audit+".state", []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	engine := NewRecoveryEngine(audit)
	cfg := RecoveryConfig{Enabled: true, DryRun: true, AuditLog: audit}
	runs, warnings := engine.Evaluate(context.Background(), nil, cfg, time.Now())
	if len(runs) != 0 || len(warnings) != 1 || !strings.Contains(warnings[0], "actions disabled") {
		t.Fatalf("corrupt state did not fail closed: runs=%v warnings=%v", runs, warnings)
	}
}

func TestRecoveryRunsRestartAndVerifiesService(t *testing.T) {
	audit := filepath.Join(t.TempDir(), "recovery.jsonl")
	cfg := RecoveryConfig{Enabled: true, AuditLog: audit, Policies: []RecoveryPolicy{{
		Name: "web", Enabled: true, Service: "web.service", FailureFor: Duration(0),
		MaxAttempts: 2, Cooldown: Duration(time.Minute), VerificationTimeout: Duration(5 * time.Second),
	}}}
	engine := NewRecoveryEngine(audit)
	restarted := false
	engine.restartUnit = func(_ context.Context, service string) error {
		if service != "web.service" {
			t.Fatalf("unexpected restart target %q", service)
		}
		restarted = true
		return nil
	}
	engine.verifyUnit = func(_ context.Context, service string, timeout time.Duration) error {
		if service != "web.service" || timeout != 5*time.Second || !restarted {
			t.Fatalf("verification called before the expected restart: service=%q timeout=%s restarted=%t", service, timeout, restarted)
		}
		return nil
	}

	runs, warnings := engine.Evaluate(context.Background(), []ServiceState{{Name: "web.service", ActiveState: "failed"}}, cfg, time.Now())
	if len(warnings) != 0 || len(runs) != 1 || runs[0].Outcome != "succeeded" || !runs[0].Verified {
		t.Fatalf("recovery result=%+v warnings=%v", runs, warnings)
	}
	contents, err := os.ReadFile(audit)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contents), `"outcome":"started"`) || !strings.Contains(string(contents), `"outcome":"succeeded"`) {
		t.Fatalf("audit does not include start and verified result: %s", contents)
	}
}

func TestRecoveryDoesNotRestartIntentionallyInactiveService(t *testing.T) {
	audit := filepath.Join(t.TempDir(), "recovery.jsonl")
	cfg := RecoveryConfig{Enabled: true, AuditLog: audit, Policies: []RecoveryPolicy{{
		Name: "web", Enabled: true, Service: "web.service", FailureFor: Duration(0),
		MaxAttempts: 2, Cooldown: Duration(time.Minute), VerificationTimeout: Duration(5 * time.Second),
	}}}
	engine := NewRecoveryEngine(audit)
	restartCalled := false
	engine.restartUnit = func(context.Context, string) error { restartCalled = true; return nil }
	engine.verifyUnit = func(context.Context, string, time.Duration) error { return nil }

	runs, warnings := engine.Evaluate(context.Background(), []ServiceState{{Name: "web.service", ActiveState: "inactive"}}, cfg, time.Now())
	if restartCalled || len(runs) != 0 || len(warnings) != 0 {
		t.Fatalf("inactive unit was automatically restarted: restart=%t runs=%+v warnings=%v", restartCalled, runs, warnings)
	}
}

func TestRecoveryWaitsForSustainedFailureDuration(t *testing.T) {
	audit := filepath.Join(t.TempDir(), "recovery.jsonl")
	cfg := RecoveryConfig{Enabled: true, AuditLog: audit, Policies: []RecoveryPolicy{{
		Name: "web", Enabled: true, Service: "web.service", FailureFor: Duration(30 * time.Second),
		MaxAttempts: 1, Cooldown: Duration(time.Minute), VerificationTimeout: Duration(5 * time.Second),
	}}}
	engine := NewRecoveryEngine(audit)
	restartCalls := 0
	engine.restartUnit = func(context.Context, string) error { restartCalls++; return nil }
	engine.verifyUnit = func(context.Context, string, time.Duration) error { return nil }
	states := []ServiceState{{Name: "web.service", ActiveState: "failed"}}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	for _, elapsed := range []time.Duration{0, 29 * time.Second} {
		runs, warnings := engine.Evaluate(context.Background(), states, cfg, now.Add(elapsed))
		if len(runs) != 0 || len(warnings) != 0 {
			t.Fatalf("recovery ran before failure duration at %s: runs=%+v warnings=%v", elapsed, runs, warnings)
		}
	}
	runs, warnings := engine.Evaluate(context.Background(), states, cfg, now.Add(30*time.Second))
	if len(warnings) != 0 || len(runs) != 1 || runs[0].Outcome != "succeeded" || restartCalls != 1 {
		t.Fatalf("recovery did not run at failure duration: runs=%+v warnings=%v restart_calls=%d", runs, warnings, restartCalls)
	}
}

func TestRecoveryDoesNotRunWithoutDurableStartAudit(t *testing.T) {
	audit := t.TempDir() // A directory is not a writable JSONL audit file.
	cfg := RecoveryConfig{Enabled: true, AuditLog: audit, Policies: []RecoveryPolicy{{
		Name: "web", Enabled: true, Service: "web.service", FailureFor: Duration(0),
		MaxAttempts: 2, Cooldown: Duration(time.Minute), VerificationTimeout: Duration(5 * time.Second),
	}}}
	engine := NewRecoveryEngine(audit)
	restartCalled := false
	engine.restartUnit = func(context.Context, string) error { restartCalled = true; return nil }
	engine.verifyUnit = func(context.Context, string, time.Duration) error { return nil }

	runs, warnings := engine.Evaluate(context.Background(), []ServiceState{{Name: "web.service", ActiveState: "failed"}}, cfg, time.Now())
	if restartCalled || len(runs) != 1 || runs[0].Outcome != "failed" || len(warnings) != 1 {
		t.Fatalf("recovery was not fail-closed: restart=%t runs=%+v warnings=%v", restartCalled, runs, warnings)
	}
	if !strings.Contains(runs[0].Error, "persist recovery start audit") {
		t.Fatalf("unexpected recovery error: %q", runs[0].Error)
	}
}

func TestRecoveryRecordsVerificationFailure(t *testing.T) {
	audit := filepath.Join(t.TempDir(), "recovery.jsonl")
	cfg := RecoveryConfig{Enabled: true, AuditLog: audit, Policies: []RecoveryPolicy{{
		Name: "web", Enabled: true, Service: "web.service", FailureFor: Duration(0),
		MaxAttempts: 2, Cooldown: Duration(time.Minute), VerificationTimeout: Duration(5 * time.Second),
	}}}
	engine := NewRecoveryEngine(audit)
	engine.restartUnit = func(context.Context, string) error { return nil }
	engine.verifyUnit = func(context.Context, string, time.Duration) error { return errors.New("service stayed failed") }

	runs, warnings := engine.Evaluate(context.Background(), []ServiceState{{Name: "web.service", ActiveState: "failed"}}, cfg, time.Now())
	if len(warnings) != 0 || len(runs) != 1 || runs[0].Outcome != "failed" || runs[0].Verified || runs[0].Error != "service stayed failed" {
		t.Fatalf("verification failure was not recorded: runs=%+v warnings=%v", runs, warnings)
	}
}
