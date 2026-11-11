package agent

import "math"

type HealthWeights struct {
	CPU      float64 `json:"cpu"`
	Memory   float64 `json:"memory"`
	Disk     float64 `json:"disk"`
	Services float64 `json:"services"`
	Network  float64 `json:"network"`
	Agent    float64 `json:"agent"`
}

func DefaultHealthWeights() HealthWeights {
	return HealthWeights{CPU: 20, Memory: 20, Disk: 20, Services: 25, Network: 10, Agent: 5}
}

// ScoreHealth applies the documented weighted component scores. It is an
// operational summary, not a guarantee of host reliability.
func ScoreHealth(report Report, online bool, weights HealthWeights) (int, map[string]int) {
	if weights == (HealthWeights{}) {
		weights = DefaultHealthWeights()
	}
	components := map[string]int{
		"cpu":      inversePercent(report.CPU.UsagePercent),
		"memory":   inversePercent(report.Memory.UsagePercent),
		"disk":     diskHealth(report.Disks),
		"services": serviceHealth(report.Services),
		"network":  networkHealth(report.Network),
		"agent":    0,
	}
	if online {
		components["agent"] = 100
	}
	totalWeight := weights.CPU + weights.Memory + weights.Disk + weights.Services + weights.Network + weights.Agent
	if totalWeight <= 0 {
		weights = DefaultHealthWeights()
		totalWeight = 100
	}
	score := float64(components["cpu"])*weights.CPU +
		float64(components["memory"])*weights.Memory +
		float64(components["disk"])*weights.Disk +
		float64(components["services"])*weights.Services +
		float64(components["network"])*weights.Network +
		float64(components["agent"])*weights.Agent
	return int(math.Round(score / totalWeight)), components
}

func inversePercent(value float64) int {
	return int(math.Round(100 - math.Max(0, math.Min(100, value))))
}

func diskHealth(disks []Disk) int {
	if len(disks) == 0 {
		return 100
	}
	worst := 0.0
	for _, disk := range disks {
		worst = math.Max(worst, disk.UsagePercent)
	}
	return inversePercent(worst)
}

func serviceHealth(services []ServiceState) int {
	if len(services) == 0 {
		return 100
	}
	active := 0
	for _, service := range services {
		if service.ActiveState == "active" {
			active++
		}
	}
	return int(math.Round(float64(active) * 100 / float64(len(services))))
}

func networkHealth(interfaces []NetCounters) int {
	var packets, errorsAndDrops uint64
	for _, iface := range interfaces {
		packets += iface.RXPackets + iface.TXPackets
		errorsAndDrops += iface.RXErrors + iface.TXErrors + iface.RXDrops + iface.TXDrops
	}
	if packets == 0 {
		if errorsAndDrops == 0 {
			return 100
		}
		return 0
	}
	return inversePercent(float64(errorsAndDrops) * 100 / float64(packets))
}
