package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type RecoveryEngine struct {
	failureSince map[string]time.Time
	lastAttempt  map[string]time.Time
	attempts     map[string]int
	statePath    string
	loadErr      error
	restartUnit  func(context.Context, string) error
	verifyUnit   func(context.Context, string, time.Duration) error
}

func NewRecoveryEngine(auditPaths ...string) *RecoveryEngine {
	e := &RecoveryEngine{
		failureSince: make(map[string]time.Time),
		lastAttempt:  make(map[string]time.Time),
		attempts:     make(map[string]int),
		restartUnit:  restartService,
		verifyUnit:   verifyService,
	}
	if len(auditPaths) > 0 && auditPaths[0] != "" {
		e.statePath = auditPaths[0] + ".state"
		e.loadErr = e.loadState()
	}
	return e
}

func (e *RecoveryEngine) Evaluate(ctx context.Context, states []ServiceState, cfg RecoveryConfig, now time.Time) ([]RecoveryExecution, []string) {
	if !cfg.Enabled {
		return nil, nil
	}
	if e.loadErr != nil {
		return nil, []string{fmt.Sprintf("recovery state unavailable; actions disabled: %v", e.loadErr)}
	}
	byName := make(map[string]ServiceState, len(states))
	for _, state := range states {
		byName[state.Name] = state
	}
	var executions []RecoveryExecution
	var warnings []string
	for _, policy := range cfg.Policies {
		if !policy.Enabled {
			continue
		}
		state, exists := byName[policy.Service]
		if !exists {
			continue // A failed D-Bus read is not evidence that the service failed.
		}
		if state.ActiveState != "failed" {
			delete(e.failureSince, policy.Name)
			if state.ActiveState == "active" {
				e.attempts[policy.Name] = 0
			}
			continue
		}
		failedAt, exists := e.failureSince[policy.Name]
		if !exists {
			failedAt = now
			e.failureSince[policy.Name] = failedAt
			if err := e.saveState(); err != nil {
				warnings = append(warnings, fmt.Sprintf("recovery state: %v", err))
				continue
			}
		}
		if now.Sub(failedAt) < policy.FailureFor.Value() {
			continue
		}
		if last, attempted := e.lastAttempt[policy.Name]; attempted && now.Sub(last) < policy.Cooldown.Value() {
			continue
		}
		if e.attempts[policy.Name] >= policy.MaxAttempts {
			continue
		}

		execution := RecoveryExecution{Policy: policy.Name, Service: policy.Service, StartedAt: now.UTC()}
		e.lastAttempt[policy.Name] = now
		willRun := !policy.RequireApproval && !cfg.DryRun
		if willRun {
			e.attempts[policy.Name]++
		}
		if err := e.saveState(); err != nil {
			if willRun {
				e.attempts[policy.Name]--
			}
			execution.Outcome = "failed"
			execution.Error = fmt.Sprintf("persist recovery state before action: %v", err)
			execution.FinishedAt = time.Now().UTC()
			executions = append(executions, execution)
			continue
		}
		if cfg.AuditLog != "" {
			started := execution
			started.Outcome = "started"
			if err := appendRecoveryAudit(cfg.AuditLog, started); err != nil {
				execution.Outcome = "failed"
				execution.Error = fmt.Sprintf("persist recovery start audit before action: %v", err)
				execution.FinishedAt = time.Now().UTC()
				executions = append(executions, execution)
				warnings = append(warnings, fmt.Sprintf("recovery audit log: %v", err))
				continue
			}
		}
		switch {
		case policy.RequireApproval:
			execution.Outcome = "approval_required"
		case cfg.DryRun:
			execution.Outcome = "dry_run"
		default:
			if err := e.restartUnit(ctx, policy.Service); err != nil {
				execution.Outcome = "failed"
				execution.Error = err.Error()
			} else if err := e.verifyUnit(ctx, policy.Service, policy.VerificationTimeout.Value()); err != nil {
				execution.Outcome = "failed"
				execution.Error = err.Error()
			} else {
				execution.Outcome = "succeeded"
				execution.Verified = true
			}
		}
		execution.FinishedAt = time.Now().UTC()
		executions = append(executions, execution)
		if cfg.AuditLog != "" {
			if err := appendRecoveryAudit(cfg.AuditLog, execution); err != nil {
				warnings = append(warnings, fmt.Sprintf("recovery audit log: %v", err))
			}
		}
	}
	if err := e.saveState(); err != nil {
		warnings = append(warnings, fmt.Sprintf("recovery state: %v", err))
	}
	return executions, warnings
}

type recoveryState struct {
	FailureSince map[string]time.Time `json:"failure_since"`
	LastAttempt  map[string]time.Time `json:"last_attempt"`
	Attempts     map[string]int       `json:"attempts"`
}

func (e *RecoveryEngine) loadState() error {
	data, err := os.ReadFile(e.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var state recoveryState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}
	if state.FailureSince != nil {
		e.failureSince = state.FailureSince
	}
	if state.LastAttempt != nil {
		e.lastAttempt = state.LastAttempt
	}
	if state.Attempts != nil {
		e.attempts = state.Attempts
	}
	return nil
}

func (e *RecoveryEngine) saveState() error {
	if e.statePath == "" {
		return nil
	}
	directory := filepath.Dir(e.statePath)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(recoveryState{FailureSince: e.failureSince, LastAttempt: e.lastAttempt, Attempts: e.attempts})
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(directory, ".hostsentry-recovery-state-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, e.statePath); err != nil {
		return err
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryFile.Close()
	return directoryFile.Sync()
}

func verifyService(ctx context.Context, name string, timeout time.Duration) error {
	verifyCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		state, err := readServiceStateForRecovery(verifyCtx, name)
		if err == nil && state.ActiveState == "active" {
			return nil
		}
		select {
		case <-verifyCtx.Done():
			if err != nil {
				return fmt.Errorf("verification timed out: %w", err)
			}
			return fmt.Errorf("service did not become active before timeout (state=%s/%s)", state.ActiveState, state.SubState)
		case <-ticker.C:
		}
	}
}

func appendRecoveryAudit(path string, execution RecoveryExecution) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if info, err := os.Stat(path); err == nil && info.Size() >= 10<<20 {
		if err := os.Rename(path, path+".1"); err != nil {
			return fmt.Errorf("rotate recovery audit: %w", err)
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if err := json.NewEncoder(file).Encode(execution); err != nil {
		return err
	}
	return file.Sync()
}
