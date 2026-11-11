// Command hostsentry-agent collects and prints health reports from a Linux host.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/hostsentry/hostsentry/internal/agent"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "hostsentry-agent:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("hostsentry-agent", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "", "YAML configuration file")
	outputPath := flags.String("output", "-", "report destination ('-' for stdout)")
	once := flags.Bool("once", false, "collect one report and exit")
	showVersion := flags.Bool("version", false, "print version and exit")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		_, err := fmt.Fprintln(stdout, version)
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", flags.Args())
	}

	cfg, err := agent.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	collector := agent.NewCollector(version, cfg.ProcessLimit, cfg.Services...)
	evaluator := agent.NewEvaluator()
	recovery := agent.NewRecoveryEngine(cfg.Recovery.AuditLog)
	effectiveRecovery := cfg.Recovery
	logger := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var remote *agent.RemoteReporter
	if cfg.Central.URL != "" {
		remote, err = agent.NewRemoteReporter(cfg.Central)
		if err != nil {
			return err
		}
		if !*once {
			go remote.Run(ctx, logger)
		}
	}
	var currentPolicyVersion int64

	write := func() error {
		report, collectErr := collector.Collect(ctx)
		if collectErr != nil {
			return collectErr
		}
		report.PolicyVersion = currentPolicyVersion
		report.Recoveries = []agent.RecoveryExecution{}
		report.Alerts = evaluator.Evaluate(report, cfg.Thresholds, cfg.SustainFor.Value(), report.CollectedAt)
		if remote != nil && cfg.Recovery.AllowRemotePolicies {
			bundle, syncErr := remote.FetchPolicies(ctx)
			if syncErr != nil {
				report.Warnings = append(report.Warnings, fmt.Sprintf("central policy sync: %v", syncErr))
			} else {
				candidate := cfg
				candidate.Recovery.Policies = bundle.Policies
				if validateErr := candidate.Validate(); validateErr != nil {
					report.Warnings = append(report.Warnings, fmt.Sprintf("central policy rejected: %v", validateErr))
				} else {
					effectiveRecovery = cfg.Recovery
					effectiveRecovery.Policies = bundle.Policies
					effectiveRecovery.Enabled = cfg.Recovery.Enabled && bundle.Enabled
					effectiveRecovery.DryRun = cfg.Recovery.DryRun || bundle.DryRun
					currentPolicyVersion = bundle.Version
					report.PolicyVersion = currentPolicyVersion
				}
			}
		}
		report.Recoveries, report.Warnings = appendRecoveries(report, recovery, effectiveRecovery, ctx)
		if remote != nil {
			if err := remote.Enqueue(report); err != nil {
				report.Warnings = append(report.Warnings, fmt.Sprintf("central queue: %v", err))
			}
		}
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return fmt.Errorf("encode report: %w", err)
		}
		if *outputPath == "-" {
			_, err = fmt.Fprintln(stdout, string(data))
		} else {
			err = writeReport(*outputPath, data)
		}
		if err != nil {
			return err
		}
		if remote != nil && *once {
			if err := remote.Flush(ctx); err != nil {
				logger.Warn("central report delivery deferred", "error", err)
			}
		}
		logger.Info("health report collected", "host", report.System.Hostname, "warnings", len(report.Warnings), "alerts", len(report.Alerts))
		return nil
	}
	if *once {
		return write()
	}
	if err := write(); err != nil {
		logger.Error("collection failed", "error", err)
	}
	ticker := time.NewTicker(cfg.Interval.Value())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := write(); err != nil {
				logger.Error("collection failed", "error", err)
			}
		}
	}
}

func appendRecoveries(report agent.Report, engine *agent.RecoveryEngine, cfg agent.RecoveryConfig, ctx context.Context) ([]agent.RecoveryExecution, []string) {
	executions, warnings := engine.Evaluate(ctx, report.Services, cfg, report.CollectedAt)
	return executions, append(report.Warnings, warnings...)
}

func writeReport(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create report directory: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".hostsentry-*.tmp")
	if err != nil {
		return fmt.Errorf("create report file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o640); err != nil {
		tmp.Close()
		return fmt.Errorf("set report permissions: %w", err)
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return fmt.Errorf("write report: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync report: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close report: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("publish report: %w", err)
	}
	if directory, err := os.Open(filepath.Dir(path)); err == nil {
		defer directory.Close()
		if err := directory.Sync(); err != nil {
			return fmt.Errorf("sync report directory: %w", err)
		}
	}
	return nil
}
