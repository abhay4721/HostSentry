package agent

import (
	"fmt"
	"sort"
	"time"
)

type Report struct {
	SchemaVersion string         `json:"schema_version"`
	CollectedAt   time.Time      `json:"collected_at"`
	System        System         `json:"system"`
	CPU           CPU            `json:"cpu"`
	Memory        Memory         `json:"memory"`
	Disks         []Disk         `json:"disks"`
	DiskIO        []DiskIO       `json:"disk_io"`
	Processes     []Process      `json:"processes"`
	Interfaces    []NetInterface `json:"interfaces"`
	Network       []NetCounters  `json:"network"`
	Alerts        []Alert        `json:"alerts"`
	Warnings      []string       `json:"warnings"`
}

type System struct {
	Hostname             string    `json:"hostname"`
	OS                   string    `json:"os"`
	Distribution         string    `json:"distribution"`
	DistributionVersion  string    `json:"distribution_version,omitempty"`
	KernelVersion        string    `json:"kernel_version"`
	Architecture         string    `json:"architecture"`
	BootTime             time.Time `json:"boot_time"`
	UptimeSeconds        uint64    `json:"uptime_seconds"`
	AgentVersion         string    `json:"agent_version"`
}

type CPU struct {
	UsagePercent  float64   `json:"usage_percent"`
	Cores         []float64 `json:"core_usage_percent"`
	Load1         float64   `json:"load_1"`
	Load5         float64   `json:"load_5"`
	Load15        float64   `json:"load_15"`
	UserSeconds   float64   `json:"user_seconds"`
	SystemSeconds float64   `json:"system_seconds"`
	IdleSeconds   float64   `json:"idle_seconds"`
}

type Memory struct {
	TotalBytes      uint64   `json:"total_bytes"`
	UsedBytes       uint64   `json:"used_bytes"`
	AvailableBytes  uint64   `json:"available_bytes"`
	UsagePercent    float64  `json:"usage_percent"`
	SwapTotalBytes  uint64   `json:"swap_total_bytes"`
	SwapUsedBytes   uint64   `json:"swap_used_bytes"`
	SwapPercent     float64  `json:"swap_usage_percent"`
	PressureAvg10   *float64 `json:"memory_pressure_avg10,omitempty"`
}

type Disk struct {
	Device         string  `json:"device"`
	Mountpoint     string  `json:"mountpoint"`
	Filesystem     string  `json:"filesystem"`
	ReadOnly       bool    `json:"read_only"`
	TotalBytes     uint64  `json:"total_bytes"`
	UsedBytes      uint64  `json:"used_bytes"`
	FreeBytes      uint64  `json:"free_bytes"`
	UsagePercent   float64 `json:"usage_percent"`
	InodesTotal    uint64  `json:"inodes_total,omitempty"`
	InodesUsed     uint64  `json:"inodes_used,omitempty"`
	InodesPercent  float64 `json:"inodes_usage_percent,omitempty"`
}

type DiskIO struct {
	Device     string `json:"device"`
	ReadBytes  uint64 `json:"read_bytes"`
	WriteBytes uint64 `json:"write_bytes"`
	ReadCount  uint64 `json:"read_count"`
	WriteCount uint64 `json:"write_count"`
}

type Process struct {
	PID           int32      `json:"pid"`
	Name          string     `json:"name"`
	CPUPercent    float64    `json:"cpu_percent"`
	MemoryBytes   uint64     `json:"memory_bytes"`
	Threads       int32      `json:"threads"`
	Status        string     `json:"status"`
	StartedAt     *time.Time `json:"started_at,omitempty"`
	UptimeSeconds uint64     `json:"uptime_seconds"`
}

type NetInterface struct {
	Name            string   `json:"name"`
	MTU             int      `json:"mtu"`
	HardwareAddress string   `json:"hardware_address,omitempty"`
	Flags           []string `json:"flags"`
	Up              bool     `json:"up"`
}

type NetCounters struct {
	Name      string `json:"name"`
	RXBytes   uint64 `json:"rx_bytes"`
	TXBytes   uint64 `json:"tx_bytes"`
	RXPackets uint64 `json:"rx_packets"`
	TXPackets uint64 `json:"tx_packets"`
	RXErrors  uint64 `json:"rx_errors"`
	TXErrors  uint64 `json:"tx_errors"`
	RXDrops   uint64 `json:"rx_drops"`
	TXDrops   uint64 `json:"tx_drops"`
}

type Alert struct {
	Metric    string    `json:"metric"`
	Value     float64   `json:"value"`
	Threshold float64   `json:"threshold"`
	Since     time.Time `json:"since"`
	Message   string    `json:"message"`
}

type thresholdState struct{ aboveSince time.Time }
type Evaluator struct{ state map[string]thresholdState }

func NewEvaluator() *Evaluator { return &Evaluator{state: make(map[string]thresholdState)} }

func (e *Evaluator) Evaluate(report Report, thresholds Thresholds, sustain time.Duration, now time.Time) []Alert {
	checks := []struct {
		key string
		value, limit float64
	}{
		{"cpu", report.CPU.UsagePercent, thresholds.CPUPercent},
		{"memory", report.Memory.UsagePercent, thresholds.MemoryPercent},
	}
	for _, disk := range report.Disks {
		checks = append(checks, struct { key string; value, limit float64 }{fmt.Sprintf("disk:%s", disk.Mountpoint), disk.UsagePercent, thresholds.DiskPercent})
	}
	active := make(map[string]bool, len(checks))
	alerts := make([]Alert, 0)
	for _, check := range checks {
		if check.limit <= 0 || check.value <= check.limit { continue }
		active[check.key] = true
		state, ok := e.state[check.key]
		if !ok { state.aboveSince = now; e.state[check.key] = state }
		if now.Sub(state.aboveSince) >= sustain {
			alerts = append(alerts, Alert{Metric: check.key, Value: check.value, Threshold: check.limit, Since: state.aboveSince, Message: fmt.Sprintf("%s usage %.1f%% has remained above %.1f%%", check.key, check.value, check.limit)})
		}
	}
	for key := range e.state { if !active[key] { delete(e.state, key) } }
	sort.Slice(alerts, func(i, j int) bool { return alerts[i].Metric < alerts[j].Metric })
	return alerts
}
