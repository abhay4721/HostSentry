package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type RemoteReporter struct {
	agentID string
	url     string
	baseURL string
	client  *http.Client
	queue   *ReportQueue
	wake    chan struct{}
	mu      sync.Mutex
}

func NewRemoteReporter(cfg CentralConfig) (*RemoteReporter, error) {
	certificate, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("load central client certificate: %w", err)
	}
	caPEM, err := os.ReadFile(cfg.CACertificate)
	if err != nil {
		return nil, fmt.Errorf("read central CA certificate: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("central CA file contains no valid certificates")
	}
	timeout := cfg.RequestTimeout.Value()
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      roots,
		Certificates: []tls.Certificate{certificate},
	}}
	return &RemoteReporter{
		agentID: cfg.AgentID,
		url:     strings.TrimRight(cfg.URL, "/") + "/api/v1/agent/reports",
		baseURL: strings.TrimRight(cfg.URL, "/"),
		client:  &http.Client{Transport: transport, Timeout: timeout},
		queue:   NewReportQueue(cfg.QueuePath, cfg.QueueMaxBytes),
		wake:    make(chan struct{}, 1),
	}, nil
}

type RemotePolicyBundle struct {
	Version  int64            `json:"version"`
	Enabled  bool             `json:"enabled"`
	DryRun   bool             `json:"dry_run"`
	Policies []RecoveryPolicy `json:"policies"`
}

func (r *RemoteReporter) FetchPolicies(ctx context.Context) (RemotePolicyBundle, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, r.baseURL+"/api/v1/agent/policies", nil)
	if err != nil {
		return RemotePolicyBundle{}, err
	}
	request.Header.Set("X-HostSentry-Agent", r.agentID)
	response, err := r.client.Do(request)
	if err != nil {
		return RemotePolicyBundle{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return RemotePolicyBundle{}, fmt.Errorf("central server returned HTTP %d for policy sync", response.StatusCode)
	}
	var bundle RemotePolicyBundle
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&bundle); err != nil {
		return RemotePolicyBundle{}, fmt.Errorf("decode policy bundle: %w", err)
	}
	return bundle, nil
}

func (r *RemoteReporter) Enqueue(report Report) error {
	id := r.agentID + ":" + report.CollectedAt.UTC().Format(time.RFC3339Nano)
	if err := r.queue.Push(queuedReport{ID: id, Report: report}); err != nil {
		return err
	}
	select {
	case r.wake <- struct{}{}:
	default:
	}
	return nil
}

func (r *RemoteReporter) Run(ctx context.Context, logger *slog.Logger) {
	delay := time.Second
	for {
		if err := r.Flush(ctx); err != nil && ctx.Err() == nil {
			logger.Warn("central report delivery failed; queued for retry", "error", err, "retry_in", delay.String())
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-r.wake:
				timer.Stop()
			case <-timer.C:
			}
			if delay < 5*time.Minute {
				delay *= 2
				if delay > 5*time.Minute {
					delay = 5 * time.Minute
				}
			}
			continue
		}
		delay = time.Second
		select {
		case <-ctx.Done():
			return
		case <-r.wake:
		}
	}
}

func (r *RemoteReporter) Flush(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for {
		item, ok, err := r.queue.Peek()
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		body, err := json.Marshal(item)
		if err != nil {
			return err
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(body))
		if err != nil {
			return err
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", item.ID)
		request.Header.Set("X-HostSentry-Agent", r.agentID)
		response, err := r.client.Do(request)
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return fmt.Errorf("central server returned HTTP %d", response.StatusCode)
		}
		if err := r.queue.Ack(item.ID); err != nil {
			return err
		}
	}
}
