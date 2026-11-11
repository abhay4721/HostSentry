package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Interval     Duration       `yaml:"interval"`
	ProcessLimit int            `yaml:"process_limit"`
	SustainFor   Duration       `yaml:"sustain_for"`
	Thresholds   Thresholds     `yaml:"thresholds"`
	Services     []string       `yaml:"services"`
	Recovery     RecoveryConfig `yaml:"recovery"`
	Central      CentralConfig  `yaml:"central"`
}

type CentralConfig struct {
	URL            string   `yaml:"url"`
	AgentID        string   `yaml:"agent_id"`
	CACertificate  string   `yaml:"ca_certificate"`
	ClientCert     string   `yaml:"client_certificate"`
	ClientKey      string   `yaml:"client_key"`
	QueuePath      string   `yaml:"queue_path"`
	QueueMaxBytes  int64    `yaml:"queue_max_bytes"`
	RequestTimeout Duration `yaml:"request_timeout"`
}

type RecoveryConfig struct {
	Enabled             bool             `yaml:"enabled" json:"enabled"`
	DryRun              bool             `yaml:"dry_run" json:"dry_run"`
	AllowRemotePolicies bool             `yaml:"allow_remote_policies" json:"-"`
	AuditLog            string           `yaml:"audit_log" json:"-"`
	Policies            []RecoveryPolicy `yaml:"policies" json:"policies"`
}

type RecoveryPolicy struct {
	Name                string   `yaml:"name" json:"name"`
	Enabled             bool     `yaml:"enabled" json:"enabled"`
	Service             string   `yaml:"service" json:"service"`
	FailureFor          Duration `yaml:"failure_for" json:"failure_for"`
	MaxAttempts         int      `yaml:"max_attempts" json:"max_attempts"`
	Cooldown            Duration `yaml:"cooldown" json:"cooldown"`
	VerificationTimeout Duration `yaml:"verification_timeout" json:"verification_timeout"`
	RequireApproval     bool     `yaml:"require_approval" json:"require_approval"`
}

type Duration time.Duration

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var value string
	if err := node.Decode(&value); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return errors.New("duration must be a string")
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}
func (d Duration) Value() time.Duration { return time.Duration(d) }

type Thresholds struct {
	CPUPercent    float64 `yaml:"cpu_percent"`
	MemoryPercent float64 `yaml:"memory_percent"`
	DiskPercent   float64 `yaml:"disk_percent"`
}

func DefaultConfig() Config {
	return Config{
		Interval: Duration(30 * time.Second), ProcessLimit: 20, SustainFor: Duration(2 * time.Minute),
		Thresholds: Thresholds{CPUPercent: 90, MemoryPercent: 90, DiskPercent: 90},
		Recovery:   RecoveryConfig{DryRun: true},
		Central:    CentralConfig{QueuePath: "/var/lib/hostsentry/queue.jsonl", QueueMaxBytes: 10 << 20, RequestTimeout: Duration(10 * time.Second)},
	}
}

func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return Config{}, fmt.Errorf("read config %q: %w", path, err)
		}
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		decoder.KnownFields(true)
		if err := decoder.Decode(&cfg); err != nil {
			return Config{}, fmt.Errorf("parse config %q: %w", path, err)
		}
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if c.Interval.Value() < time.Second || c.Interval.Value() > 24*time.Hour {
		return errors.New("interval must be between 1s and 24h")
	}
	if c.ProcessLimit < 1 || c.ProcessLimit > 1000 {
		return errors.New("process_limit must be between 1 and 1000")
	}
	if c.SustainFor.Value() < 0 || c.SustainFor.Value() > 24*time.Hour {
		return errors.New("sustain_for must be between 0 and 24h")
	}
	for name, value := range map[string]float64{
		"cpu_percent":    c.Thresholds.CPUPercent,
		"memory_percent": c.Thresholds.MemoryPercent,
		"disk_percent":   c.Thresholds.DiskPercent,
	} {
		if value < 0 || value > 100 {
			return fmt.Errorf("thresholds.%s must be between 0 and 100", name)
		}
	}
	seenServices := make(map[string]struct{}, len(c.Services))
	for _, service := range c.Services {
		if !validServiceName(service) {
			return fmt.Errorf("services contains invalid systemd unit name %q", service)
		}
		if _, exists := seenServices[service]; exists {
			return fmt.Errorf("services contains duplicate unit %q", service)
		}
		seenServices[service] = struct{}{}
	}
	policyNames := make(map[string]struct{}, len(c.Recovery.Policies))
	if (len(c.Recovery.Policies) > 0 || c.Recovery.AllowRemotePolicies) && c.Recovery.AuditLog == "" {
		return errors.New("recovery.audit_log must be configured when recovery policies are present")
	}
	if c.Recovery.AuditLog != "" && !filepath.IsAbs(c.Recovery.AuditLog) {
		return errors.New("recovery.audit_log must be an absolute path")
	}
	if c.Central.URL != "" {
		parsed, err := url.Parse(c.Central.URL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			return errors.New("central.url must be an absolute https URL")
		}
		if !validIdentifier(c.Central.AgentID) {
			return errors.New("central.agent_id must contain only letters, digits, hyphens, or underscores")
		}
		if c.Central.CACertificate == "" || c.Central.ClientCert == "" || c.Central.ClientKey == "" {
			return errors.New("central requires ca_certificate, client_certificate, and client_key for mutual TLS")
		}
		if c.Central.QueuePath == "" || !filepath.IsAbs(c.Central.QueuePath) {
			return errors.New("central.queue_path must be an absolute path")
		}
		if c.Central.QueueMaxBytes < 1024 || c.Central.QueueMaxBytes > 1<<30 {
			return errors.New("central.queue_max_bytes must be between 1 KiB and 1 GiB")
		}
		if c.Central.RequestTimeout.Value() < time.Second || c.Central.RequestTimeout.Value() > 5*time.Minute {
			return errors.New("central.request_timeout must be between 1s and 5m")
		}
	} else if c.Central.AgentID != "" || c.Central.CACertificate != "" || c.Central.ClientCert != "" || c.Central.ClientKey != "" {
		return errors.New("central credentials and agent_id require central.url")
	}
	if c.Recovery.AllowRemotePolicies && (c.Central.URL == "" || !c.Recovery.Enabled) {
		return errors.New("recovery.allow_remote_policies requires central.url and recovery.enabled")
	}
	for _, policy := range c.Recovery.Policies {
		if !validIdentifier(policy.Name) {
			return fmt.Errorf("recovery policy has invalid name %q", policy.Name)
		}
		if _, exists := policyNames[policy.Name]; exists {
			return fmt.Errorf("duplicate recovery policy %q", policy.Name)
		}
		policyNames[policy.Name] = struct{}{}
		if !policy.Enabled {
			continue
		}
		if _, allowed := seenServices[policy.Service]; !allowed {
			return fmt.Errorf("recovery policy %q service %q is not in services allowlist", policy.Name, policy.Service)
		}
		if policy.MaxAttempts < 1 || policy.MaxAttempts > 10 {
			return fmt.Errorf("recovery policy %q max_attempts must be between 1 and 10", policy.Name)
		}
		if policy.FailureFor.Value() < 0 || policy.FailureFor.Value() > 24*time.Hour {
			return fmt.Errorf("recovery policy %q failure_for must be between 0 and 24h", policy.Name)
		}
		if policy.Cooldown.Value() < time.Second || policy.Cooldown.Value() > 24*time.Hour {
			return fmt.Errorf("recovery policy %q cooldown must be between 1s and 24h", policy.Name)
		}
		if policy.VerificationTimeout.Value() < time.Second || policy.VerificationTimeout.Value() > 5*time.Minute {
			return fmt.Errorf("recovery policy %q verification_timeout must be between 1s and 5m", policy.Name)
		}
	}
	return nil
}

func validServiceName(name string) bool {
	if len(name) < len("x.service") || !strings.HasSuffix(name, ".service") {
		return false
	}
	for _, char := range name {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || strings.ContainsRune("_.:@-", char) {
			continue
		}
		return false
	}
	return true
}

func validIdentifier(name string) bool {
	if name == "" {
		return false
	}
	for _, char := range name {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '-' || char == '_' {
			continue
		}
		return false
	}
	return true
}
