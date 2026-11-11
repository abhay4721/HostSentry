package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type historyPoint struct {
	Timestamp float64 `json:"timestamp"`
	Value     float64 `json:"value"`
}

type historySeries struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels,omitempty"`
	Points []historyPoint    `json:"points"`
}

func (a *API) SetPrometheusURL(raw string) error {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	if raw == "" {
		a.prometheusURL = ""
		return nil
	}
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("HOSTSENTRY_PROMETHEUS_URL must be an http(s) origin without credentials, path, or query")
	}
	a.prometheusURL = raw
	return nil
}

func (a *API) hostMetricHistory(w http.ResponseWriter, r *http.Request) {
	if a.prometheusURL == "" {
		writeError(w, http.StatusServiceUnavailable, "metrics_history_unavailable", "Prometheus history is not configured")
		return
	}
	hostID := r.PathValue("id")
	if !validAgentID(hostID) {
		writeError(w, http.StatusBadRequest, "invalid_host_id", "host id is invalid")
		return
	}
	metric := r.URL.Query().Get("metric")
	span := r.URL.Query().Get("range")
	if span == "" {
		span = "6h"
	}
	window, step, ok := metricWindow(span)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_range", "range must be 15m, 1h, 6h, or 24h")
		return
	}
	queries := historyQueries(metric, hostID)
	if len(queries) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_metric", "metric must be cpu, memory, disk, or network")
		return
	}
	end := time.Now().UTC()
	start := end.Add(-window)
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 5 * time.Second}
	series := make([]historySeries, 0)
	for _, query := range queries {
		items, err := queryPrometheusRange(ctx, client, a.prometheusURL, query.expression, start, end, step)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "metrics_history_unavailable", "Prometheus history query failed")
			return
		}
		for _, item := range items {
			name := query.name
			if query.label != "" && item.Labels[query.label] != "" {
				name += " " + item.Labels[query.label]
			}
			series = append(series, historySeries{Name: name, Labels: item.Labels, Points: item.Points})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"metric": metric, "range": span, "step_seconds": int(step.Seconds()), "series": series})
}

type historyQuery struct {
	name       string
	label      string
	expression string
}

func historyQueries(metric, hostID string) []historyQuery {
	selector := `{host_id="` + hostID + `"}`
	switch metric {
	case "cpu":
		return []historyQuery{{name: "CPU", expression: "hostsentry_agent_cpu_usage_percent" + selector}}
	case "memory":
		return []historyQuery{{name: "Memory", expression: "hostsentry_agent_memory_usage_percent" + selector}}
	case "disk":
		return []historyQuery{{name: "Disk", label: "mountpoint", expression: "hostsentry_agent_disk_usage_percent" + selector}}
	case "network":
		return []historyQuery{
			{name: "RX", label: "interface", expression: "hostsentry_agent_network_receive_bytes_per_second" + selector},
			{name: "TX", label: "interface", expression: "hostsentry_agent_network_transmit_bytes_per_second" + selector},
		}
	default:
		return nil
	}
}

type prometheusRangeResult struct {
	Labels map[string]string
	Points []historyPoint
}

func queryPrometheusRange(ctx context.Context, client *http.Client, baseURL, expression string, start, end time.Time, step time.Duration) ([]prometheusRangeResult, error) {
	endpoint, err := url.Parse(baseURL + "/api/v1/query_range")
	if err != nil {
		return nil, err
	}
	values := endpoint.Query()
	values.Set("query", expression)
	values.Set("start", strconv.FormatFloat(float64(start.UnixNano())/1e9, 'f', -1, 64))
	values.Set("end", strconv.FormatFloat(float64(end.UnixNano())/1e9, 'f', -1, 64))
	values.Set("step", strconv.Itoa(int(step.Seconds())))
	endpoint.RawQuery = values.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Prometheus returned HTTP %d", response.StatusCode)
	}
	var payload struct {
		Status string `json:"status"`
		Error  string `json:"error"`
		Data   struct {
			Result []struct {
				Metric map[string]string   `json:"metric"`
				Values [][]json.RawMessage `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 4<<20))
	if err := decoder.Decode(&payload); err != nil {
		return nil, err
	}
	if payload.Status != "success" {
		return nil, fmt.Errorf("Prometheus query failed: %s", payload.Error)
	}
	results := make([]prometheusRangeResult, 0, len(payload.Data.Result))
	for _, result := range payload.Data.Result {
		item := prometheusRangeResult{Labels: result.Metric, Points: make([]historyPoint, 0, len(result.Values))}
		for _, pair := range result.Values {
			if len(pair) != 2 {
				return nil, errors.New("Prometheus returned an invalid sample")
			}
			var timestamp float64
			var rawValue string
			if err := json.Unmarshal(pair[0], &timestamp); err != nil {
				return nil, err
			}
			if err := json.Unmarshal(pair[1], &rawValue); err != nil {
				return nil, err
			}
			value, err := strconv.ParseFloat(rawValue, 64)
			if err != nil {
				return nil, err
			}
			item.Points = append(item.Points, historyPoint{Timestamp: timestamp, Value: value})
		}
		results = append(results, item)
	}
	return results, nil
}

func metricWindow(span string) (time.Duration, time.Duration, bool) {
	switch span {
	case "15m":
		return 15 * time.Minute, 15 * time.Second, true
	case "1h":
		return time.Hour, 30 * time.Second, true
	case "6h":
		return 6 * time.Hour, 2 * time.Minute, true
	case "24h":
		return 24 * time.Hour, 5 * time.Minute, true
	default:
		return 0, 0, false
	}
}
