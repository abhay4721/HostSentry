package server

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/hostsentry/hostsentry/internal/agent"
)

type metricSample struct {
	name  string
	value float64
}

func (a *API) updateBaselinesAndDetect(ctx context.Context, tx *sql.Tx, hostID string, report agent.Report, now time.Time) ([]incidentInput, error) {
	var samples []metricSample
	if !warningFor(report.Warnings, "cpu utilization") {
		samples = append(samples, metricSample{name: "cpu", value: report.CPU.UsagePercent})
	}
	if !warningFor(report.Warnings, "memory") {
		samples = append(samples, metricSample{name: "memory", value: report.Memory.UsagePercent})
	}
	if !warningFor(report.Warnings, "filesystem") {
		for _, disk := range report.Disks {
			samples = append(samples, metricSample{name: "disk:" + disk.Mountpoint, value: disk.UsagePercent})
		}
	}
	var incidents []incidentInput
	for _, sample := range samples {
		var count int64
		var mean, squaredDeviation float64
		err := tx.QueryRowContext(ctx, `SELECT sample_count,mean,squared_deviation_sum FROM metric_baselines WHERE host_id=$1 AND metric=$2 FOR UPDATE`, hostID, sample.name).Scan(&count, &mean, &squaredDeviation)
		if err != nil && err != sql.ErrNoRows {
			return nil, err
		}
		if err == sql.ErrNoRows {
			_, err = tx.ExecContext(ctx, `INSERT INTO metric_baselines(host_id,metric,sample_count,mean,squared_deviation_sum,updated_at) VALUES ($1,$2,1,$3,0,$4)`, hostID, sample.name, sample.value, now)
			if err != nil {
				return nil, err
			}
			continue
		}
		if count >= a.anomaly.MinimumSamples {
			deviation := 1.0
			if count > 1 && squaredDeviation > 0 {
				deviation = math.Max(1, math.Sqrt(squaredDeviation/float64(count-1)))
			}
			threshold := mean + a.anomaly.Sigma*deviation
			if sample.value > threshold {
				fingerprint := "anomaly:" + sample.name
				incidents = append(incidents, incidentInput{
					fingerprint:  fingerprint,
					incidentType: "resource_anomaly",
					severity:     "warning",
					description:  fmt.Sprintf("%s utilization %.1f%% exceeded its baseline %.1f%% by %.1f standard deviations", sample.name, sample.value, mean, a.anomaly.Sigma),
				})
			}
		}
		nextCount := count + 1
		delta := sample.value - mean
		nextMean := mean + delta/float64(nextCount)
		nextSquaredDeviation := squaredDeviation + delta*(sample.value-nextMean)
		if _, err := tx.ExecContext(ctx, `UPDATE metric_baselines SET sample_count=$3,mean=$4,squared_deviation_sum=$5,updated_at=$6 WHERE host_id=$1 AND metric=$2`, hostID, sample.name, nextCount, nextMean, nextSquaredDeviation, now); err != nil {
			return nil, err
		}
	}
	return incidents, nil
}

func warningFor(warnings []string, prefix string) bool {
	for _, warning := range warnings {
		if strings.HasPrefix(warning, prefix) {
			return true
		}
	}
	return false
}
