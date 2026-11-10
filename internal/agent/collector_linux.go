//go:build linux

package agent

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

type Collector struct {
	version      string
	processLimit int
}

func NewCollector(version string, processLimit int) *Collector {
	if processLimit < 1 { processLimit = 20 }
	return &Collector{version: version, processLimit: processLimit}
}

func (c *Collector) Collect(ctx context.Context) (Report, error) {
	now := time.Now().UTC()
	r := Report{SchemaVersion: "1", CollectedAt: now}
	warn := func(section string, err error) { r.Warnings = append(r.Warnings, fmt.Sprintf("%s: %v", section, err)) }

	if info, err := host.InfoWithContext(ctx); err != nil {
		warn("system", err)
	} else {
		boot := time.Unix(int64(info.BootTime), 0).UTC()
		r.System = System{Hostname: info.Hostname, OS: info.OS, Distribution: info.Platform, DistributionVersion: info.PlatformVersion, KernelVersion: info.KernelVersion, Architecture: info.KernelArch, BootTime: boot, UptimeSeconds: info.Uptime, AgentVersion: c.version}
	}
	if r.System.BootTime.IsZero() {
		if boot, err := host.BootTimeWithContext(ctx); err == nil { r.System.BootTime = time.Unix(int64(boot), 0).UTC() } else { warn("boot time", err) }
	}
	if r.System.UptimeSeconds == 0 {
		if uptime, err := host.UptimeWithContext(ctx); err == nil { r.System.UptimeSeconds = uptime } else { warn("uptime", err) }
	}

	if totals, err := cpu.TimesWithContext(ctx, false); err != nil {
		warn("cpu times", err)
	} else if len(totals) > 0 {
		r.CPU.UserSeconds = totals[0].User
		r.CPU.SystemSeconds = totals[0].System
		r.CPU.IdleSeconds = totals[0].Idle
	}
	if percentages, err := cpu.PercentWithContext(ctx, 0, true); err != nil {
		warn("cpu utilization", err)
	} else if len(percentages) > 0 {
		r.CPU.Cores = percentages
		var sum float64
		for _, percentage := range percentages { sum += percentage }
		r.CPU.UsagePercent = sum / float64(len(percentages))
	}
	if average, err := load.AvgWithContext(ctx); err != nil {
		warn("load average", err)
	} else {
		r.CPU.Load1, r.CPU.Load5, r.CPU.Load15 = average.Load1, average.Load5, average.Load15
	}

	if vm, err := mem.VirtualMemoryWithContext(ctx); err != nil {
		warn("memory", err)
	} else {
		r.Memory.TotalBytes, r.Memory.UsedBytes, r.Memory.AvailableBytes, r.Memory.UsagePercent = vm.Total, vm.Used, vm.Available, vm.UsedPercent
	}
	if swap, err := mem.SwapMemoryWithContext(ctx); err != nil {
		warn("swap", err)
	} else {
		r.Memory.SwapTotalBytes, r.Memory.SwapUsedBytes, r.Memory.SwapPercent = swap.Total, swap.Used, swap.UsedPercent
	}
	r.Memory.PressureAvg10 = readMemoryPressure()

	partitions, err := disk.PartitionsWithContext(ctx, true)
	if err != nil {
		warn("filesystem list", err)
	} else {
		for _, partition := range partitions {
			usage, usageErr := disk.UsageWithContext(ctx, partition.Mountpoint)
			if usageErr != nil { warn("filesystem "+partition.Mountpoint, usageErr); continue }
			item := Disk{Device: partition.Device, Mountpoint: partition.Mountpoint, Filesystem: partition.Fstype, ReadOnly: hasOption(partition.Opts, "ro"), TotalBytes: usage.Total, UsedBytes: usage.Used, FreeBytes: usage.Free, UsagePercent: usage.UsedPercent, InodesTotal: usage.InodesTotal, InodesUsed: usage.InodesUsed, InodesPercent: usage.InodesUsedPercent}
			r.Disks = append(r.Disks, item)
		}
	}
	if counters, err := disk.IOCountersWithContext(ctx); err != nil {
		warn("disk I/O", err)
	} else {
		for name, stat := range counters { r.DiskIO = append(r.DiskIO, DiskIO{Device: name, ReadBytes: stat.ReadBytes, WriteBytes: stat.WriteBytes, ReadCount: stat.ReadCount, WriteCount: stat.WriteCount}) }
		sort.Slice(r.DiskIO, func(i, j int) bool { return r.DiskIO[i].Device < r.DiskIO[j].Device })
	}

	if interfaces, err := net.InterfacesWithContext(ctx); err != nil {
		warn("network interfaces", err)
	} else {
		for _, item := range interfaces { flags := append([]string(nil), item.Flags...); r.Interfaces = append(r.Interfaces, NetInterface{Name: item.Name, MTU: item.MTU, HardwareAddress: item.HardwareAddr, Flags: flags, Up: contains(flags, "up")}) }
		sort.Slice(r.Interfaces, func(i, j int) bool { return r.Interfaces[i].Name < r.Interfaces[j].Name })
	}
	if counters, err := net.IOCountersWithContext(ctx, true); err != nil {
		warn("network counters", err)
	} else {
		for _, item := range counters { r.Network = append(r.Network, NetCounters{Name: item.Name, RXBytes: item.BytesRecv, TXBytes: item.BytesSent, RXPackets: item.PacketsRecv, TXPackets: item.PacketsSent, RXErrors: item.Errin, TXErrors: item.Errout, RXDrops: item.Dropin, TXDrops: item.Dropout}) }
		sort.Slice(r.Network, func(i, j int) bool { return r.Network[i].Name < r.Network[j].Name })
	}

	r.Processes = collectProcesses(ctx, c.processLimit, now, warn)
	return r, nil
}

func collectProcesses(ctx context.Context, limit int, now time.Time, warn func(string, error)) []Process {
	procs, err := process.ProcessesWithContext(ctx)
	if err != nil { warn("process list", err); return []Process{} }
	items := make([]Process, 0, len(procs))
	for _, proc := range procs {
		name, err := proc.NameWithContext(ctx)
		if err != nil { continue } // A process may exit while the snapshot is being read.
		item := Process{PID: proc.Pid, Name: name}
		if value, err := proc.CPUPercentWithContext(ctx); err == nil { item.CPUPercent = value }
		if value, err := proc.MemoryInfoWithContext(ctx); err == nil && value != nil { item.MemoryBytes = value.RSS }
		if value, err := proc.NumThreadsWithContext(ctx); err == nil { item.Threads = value }
		if value, err := proc.StatusWithContext(ctx); err == nil && len(value) != 0 { item.Status = strings.Join(value, ",") }
		if millis, err := proc.CreateTimeWithContext(ctx); err == nil && millis > 0 {
			started := time.UnixMilli(millis).UTC()
			item.StartedAt = &started
			if now.After(started) { item.UptimeSeconds = uint64(now.Sub(started).Seconds()) }
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].CPUPercent == items[j].CPUPercent { return items[i].MemoryBytes > items[j].MemoryBytes }
		return items[i].CPUPercent > items[j].CPUPercent
	})
	if len(items) > limit { items = items[:limit] }
	return items
}

func readMemoryPressure() *float64 {
	file, err := os.Open("/proc/pressure/memory")
	if err != nil { return nil }
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || fields[0] != "some" { continue }
		for _, field := range fields[1:] {
			if strings.HasPrefix(field, "avg10=") {
				var value float64
				if _, err := fmt.Sscan(strings.TrimPrefix(field, "avg10="), &value); err == nil { return &value }
			}
		}
	}
	return nil
}

func hasOption(options []string, want string) bool { return contains(options, want) }
func contains(values []string, want string) bool { for _, value := range values { if value == want { return true } }; return false }
