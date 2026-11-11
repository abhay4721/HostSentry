package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hostsentry/hostsentry/internal/agent"
	"github.com/hostsentry/hostsentry/internal/server"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	if err := run(); err != nil {
		slog.Error("hostsentry server stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	databaseURL := os.Getenv("HOSTSENTRY_DATABASE_URL")
	bootstrapEmail := os.Getenv("HOSTSENTRY_BOOTSTRAP_ADMIN_EMAIL")
	bootstrapPassword := os.Getenv("HOSTSENTRY_BOOTSTRAP_ADMIN_PASSWORD")
	metricsToken := os.Getenv("HOSTSENTRY_METRICS_TOKEN")
	recoveryEnabled := strings.EqualFold(os.Getenv("HOSTSENTRY_RECOVERY_ENABLED"), "true")
	recoveryDryRun := !strings.EqualFold(os.Getenv("HOSTSENTRY_RECOVERY_DRY_RUN"), "false")
	healthWeights, err := configuredHealthWeights(os.Getenv("HOSTSENTRY_HEALTH_WEIGHTS"))
	if err != nil {
		return err
	}
	anomalySettings, err := configuredAnomalySettings()
	if err != nil {
		return err
	}
	certFile := os.Getenv("HOSTSENTRY_TLS_CERT")
	keyFile := os.Getenv("HOSTSENTRY_TLS_KEY")
	clientCAFile := os.Getenv("HOSTSENTRY_CLIENT_CA")
	listenAddress := os.Getenv("HOSTSENTRY_LISTEN_ADDR")
	if listenAddress == "" {
		listenAddress = ":8443"
	}
	if databaseURL == "" || metricsToken == "" || certFile == "" || keyFile == "" || clientCAFile == "" {
		return errors.New("HOSTSENTRY_DATABASE_URL, HOSTSENTRY_METRICS_TOKEN, HOSTSENTRY_TLS_CERT, HOSTSENTRY_TLS_KEY, and HOSTSENTRY_CLIENT_CA are required")
	}
	if len(metricsToken) < 32 {
		return errors.New("HOSTSENTRY_METRICS_TOKEN must contain at least 32 characters")
	}
	clientCA, err := os.ReadFile(clientCAFile)
	if err != nil {
		return fmt.Errorf("read client CA: %w", err)
	}
	clientRoots := x509.NewCertPool()
	if !clientRoots.AppendCertsFromPEM(clientCA) {
		return errors.New("client CA file contains no valid certificates")
	}
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		return fmt.Errorf("load server TLS key pair: %w", err)
	}

	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	if err := server.Migrate(pingCtx, db); err != nil {
		return err
	}
	if err := server.BootstrapAdmin(pingCtx, db, bootstrapEmail, bootstrapPassword); err != nil {
		return err
	}

	api := server.NewAPI(db, metricsToken, healthWeights, recoveryEnabled, recoveryDryRun, anomalySettings)
	if err := api.SetPrometheusURL(os.Getenv("HOSTSENTRY_PROMETHEUS_URL")); err != nil {
		return err
	}
	notifier, err := server.NewNotifierFromEnv()
	if err != nil {
		return err
	}
	api.SetNotifier(notifier)
	apiHandler := api.Handler()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		apiHandler.ServeHTTP(w, r)
		logger.Info("http request", "method", r.Method, "path", r.URL.Path, "duration_ms", time.Since(started).Milliseconds())
	})
	httpServer := &http.Server{
		Addr:              listenAddress,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ClientAuth: tls.VerifyClientCertIfGiven,
			ClientCAs:  clientRoots,
			NextProtos: []string{"h2", "http/1.1"},
		},
	}
	serverErrors := make(chan error, 1)
	go func() { serverErrors <- httpServer.ListenAndServeTLS(certFile, keyFile) }()
	logger.Info("HostSentry central server started", "listen", listenAddress)
	select {
	case <-ctx.Done():
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		return httpServer.Shutdown(shutdownCtx)
	case err := <-serverErrors:
		if errors.Is(err, http.ErrServerClosed) || strings.Contains(err.Error(), "use of closed network connection") {
			return nil
		}
		return err
	}
}

func configuredHealthWeights(raw string) (agent.HealthWeights, error) {
	defaults := agent.DefaultHealthWeights()
	if strings.TrimSpace(raw) == "" {
		return defaults, nil
	}
	var weights agent.HealthWeights
	if err := json.Unmarshal([]byte(raw), &weights); err != nil {
		return agent.HealthWeights{}, fmt.Errorf("parse HOSTSENTRY_HEALTH_WEIGHTS: %w", err)
	}
	total := weights.CPU + weights.Memory + weights.Disk + weights.Services + weights.Network + weights.Agent
	if weights.CPU < 0 || weights.Memory < 0 || weights.Disk < 0 || weights.Services < 0 || weights.Network < 0 || weights.Agent < 0 || total != 100 {
		return agent.HealthWeights{}, errors.New("health weights must be nonnegative and sum to 100")
	}
	return weights, nil
}

func configuredAnomalySettings() (server.AnomalySettings, error) {
	settings := server.DefaultAnomalySettings()
	if raw := os.Getenv("HOSTSENTRY_ANOMALY_ENABLED"); raw != "" {
		enabled, err := strconv.ParseBool(raw)
		if err != nil {
			return settings, fmt.Errorf("parse HOSTSENTRY_ANOMALY_ENABLED: %w", err)
		}
		settings.Enabled = enabled
	}
	if raw := os.Getenv("HOSTSENTRY_ANOMALY_MIN_SAMPLES"); raw != "" {
		minimum, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || minimum < 5 || minimum > 1000 {
			return settings, errors.New("HOSTSENTRY_ANOMALY_MIN_SAMPLES must be between 5 and 1000")
		}
		settings.MinimumSamples = minimum
	}
	if raw := os.Getenv("HOSTSENTRY_ANOMALY_SIGMA"); raw != "" {
		sigma, err := strconv.ParseFloat(raw, 64)
		if err != nil || math.IsNaN(sigma) || math.IsInf(sigma, 0) || sigma < 1 || sigma > 10 {
			return settings, errors.New("HOSTSENTRY_ANOMALY_SIGMA must be between 1 and 10")
		}
		settings.Sigma = sigma
	}
	return settings, nil
}
