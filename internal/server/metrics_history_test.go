package server

import "testing"

func TestMetricHistoryRejectsUnsupportedQueriesAndRanges(t *testing.T) {
	api := &API{}
	if err := api.SetPrometheusURL("http://prometheus:9090"); err != nil {
		t.Fatalf("valid Prometheus URL rejected: %v", err)
	}
	for _, invalid := range []string{"http://user:pass@prometheus:9090", "http://prometheus:9090/prefix", "file:///tmp/prometheus", "http://prometheus:9090?query=x"} {
		if err := api.SetPrometheusURL(invalid); err == nil {
			t.Errorf("unsafe Prometheus URL accepted: %q", invalid)
		}
	}
	if queries := historyQueries("shell", "host-1"); queries != nil {
		t.Fatalf("unsupported metric created query: %+v", queries)
	}
	if _, _, ok := metricWindow("7d"); ok {
		t.Fatal("unbounded time range accepted")
	}
	for _, supported := range []string{"15m", "1h", "6h", "24h"} {
		if _, _, ok := metricWindow(supported); !ok {
			t.Errorf("supported range %q rejected", supported)
		}
	}
}
