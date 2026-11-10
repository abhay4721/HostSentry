package agent

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Interval     Duration   `yaml:"interval"`
	ProcessLimit int        `yaml:"process_limit"`
	SustainFor   Duration   `yaml:"sustain_for"`
	Thresholds   Thresholds `yaml:"thresholds"`
}

type Duration time.Duration

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var value string
	if err := node.Decode(&value); err != nil { return err }
	parsed, err := time.ParseDuration(value)
	if err != nil { return err }
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
		"cpu_percent": c.Thresholds.CPUPercent,
		"memory_percent": c.Thresholds.MemoryPercent,
		"disk_percent": c.Thresholds.DiskPercent,
	} {
		if value < 0 || value > 100 {
			return fmt.Errorf("thresholds.%s must be between 0 and 100", name)
		}
	}
	return nil
}
