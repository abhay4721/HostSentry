package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hostsentry/hostsentry/internal/agent"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestPostgresAuthAndRoleFlow(t *testing.T) {
	dsn := os.Getenv("HOSTSENTRY_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("HOSTSENTRY_TEST_DATABASE_URL is not set")
	}
	adminDB, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer adminDB.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := adminDB.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("hostsentry_test_%d", time.Now().UnixNano())
	if _, err := adminDB.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer adminDB.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	db, err := sql.Open("pgx", parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := BootstrapAdmin(ctx, db, "admin@example.org", "strong bootstrap passphrase 2026"); err != nil {
		t.Fatal(err)
	}
	if err := BootstrapAdmin(ctx, db, "", ""); err != nil {
		t.Fatalf("bootstrap should be a no-op after initial setup: %v", err)
	}
	api := NewAPI(db, "metrics-token", agent.DefaultHealthWeights(), false, true, DefaultAnomalySettings())
	handler := api.Handler()
	t.Run("agent mTLS report delivery", func(t *testing.T) {
		testAgentMTLSIngestion(t, ctx, db, api)
	})
	login := func(email, password string) (int, string) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(fmt.Sprintf(`{"email":%q,"password":%q}`, email, password)))
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		var result struct {
			Token string `json:"token"`
		}
		_ = json.Unmarshal(res.Body.Bytes(), &result)
		return res.Code, result.Token
	}
	status, adminToken := login("admin@example.org", "strong bootstrap passphrase 2026")
	if status != http.StatusOK || adminToken == "" {
		t.Fatalf("admin login status=%d", status)
	}
	listHosts := func(includeReport bool) []struct {
		ID     string          `json:"id"`
		Report json.RawMessage `json:"report"`
	} {
		query := "?limit=20"
		if includeReport {
			query += "&include_report=true"
		}
		req := httptest.NewRequest(http.MethodGet, "/api/v1/hosts"+query, nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("list hosts status=%d body=%s", res.Code, res.Body.String())
		}
		var response struct {
			Items []struct {
				ID     string          `json:"id"`
				Report json.RawMessage `json:"report"`
			} `json:"items"`
		}
		if err := json.Unmarshal(res.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		return response.Items
	}
	if items := listHosts(false); len(items) == 0 || items[0].Report != nil {
		t.Fatalf("default host list should omit full reports: %+v", items)
	}
	if items := listHosts(true); len(items) == 0 || len(items[0].Report) == 0 {
		t.Fatalf("host list with include_report=true should include snapshots: %+v", items)
	}
	userReq := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(`{"email":"viewer@example.org","display_name":"Read Only","password":"viewer password is very strong","role":"viewer"}`))
	userReq.Header.Set("Authorization", "Bearer "+adminToken)
	userRes := httptest.NewRecorder()
	handler.ServeHTTP(userRes, userReq)
	if userRes.Code != http.StatusCreated {
		t.Fatalf("create viewer status=%d body=%s", userRes.Code, userRes.Body.String())
	}
	viewerStatus, viewerToken := login("viewer@example.org", "viewer password is very strong")
	if viewerStatus != http.StatusOK || viewerToken == "" {
		t.Fatalf("viewer login status=%d", viewerStatus)
	}
	readReq := httptest.NewRequest(http.MethodGet, "/api/v1/settings", nil)
	readReq.Header.Set("Authorization", "Bearer "+viewerToken)
	readRes := httptest.NewRecorder()
	handler.ServeHTTP(readRes, readReq)
	if readRes.Code != http.StatusOK {
		t.Fatalf("viewer read status=%d", readRes.Code)
	}
	writeReq := httptest.NewRequest(http.MethodPost, "/api/v1/groups", strings.NewReader(`{"name":"restricted","host_ids":[]}`))
	writeReq.Header.Set("Authorization", "Bearer "+viewerToken)
	writeRes := httptest.NewRecorder()
	handler.ServeHTTP(writeRes, writeReq)
	if writeRes.Code != http.StatusForbidden {
		t.Fatalf("viewer admin write status=%d, want 403", writeRes.Code)
	}
	logoutReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	logoutReq.Header.Set("Authorization", "Bearer "+viewerToken)
	logoutRes := httptest.NewRecorder()
	handler.ServeHTTP(logoutRes, logoutReq)
	if logoutRes.Code != http.StatusNoContent {
		t.Fatalf("logout status=%d", logoutRes.Code)
	}
	checkReq := httptest.NewRequest(http.MethodGet, "/api/v1/settings", nil)
	checkReq.Header.Set("Authorization", "Bearer "+viewerToken)
	checkRes := httptest.NewRecorder()
	handler.ServeHTTP(checkRes, checkReq)
	if checkRes.Code != http.StatusUnauthorized {
		t.Fatalf("revoked session status=%d, want 401", checkRes.Code)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO hosts(id,hostname,last_seen,report_collected_at,latest_report) VALUES('metric-host','metric-host',now(),now(),$1::jsonb)`, `{"cpu":{"usage_percent":12.5},"memory":{"usage_percent":50,"used_bytes":1024},"system":{"uptime_seconds":3600},"disks":[{"mountpoint":"/","usage_percent":90}],"network":[{"name":"eth0","rx_bytes_per_second":20,"tx_bytes_per_second":10}],"services":[]}`); err != nil {
		t.Fatal(err)
	}
	metricsReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	metricsReq.Header.Set("Authorization", "Bearer metrics-token")
	metricsRes := httptest.NewRecorder()
	handler.ServeHTTP(metricsRes, metricsReq)
	if metricsRes.Code != http.StatusOK {
		t.Fatalf("metrics status=%d: %s", metricsRes.Code, metricsRes.Body.String())
	}
	for _, metric := range []string{"hostsentry_agent_memory_usage_bytes{host_id=\"metric-host\"} 1024", "hostsentry_agent_disk_usage_percent{host_id=\"metric-host\",mountpoint=\"/\"} 90", "hostsentry_agent_network_receive_bytes_per_second{host_id=\"metric-host\",interface=\"eth0\"} 20"} {
		if !strings.Contains(metricsRes.Body.String(), metric) {
			t.Errorf("metrics response missing %q", metric)
		}
	}

	collectedAt := time.Now().UTC().Add(-time.Minute)
	serviceReport := agent.Report{
		CollectedAt:   collectedAt,
		PolicyVersion: 7,
		System:        agent.System{Hostname: "persisted-host", AgentVersion: "test-version"},
		Services:      []agent.ServiceState{{Name: "web.service", LoadState: "loaded", ActiveState: "active", SubState: "running", MainPID: 123, Result: "success", Restarts: 2, Since: collectedAt.Add(-time.Hour)}},
	}
	if err := api.storeReport(ctx, "persisted-host", "report-1", serviceReport); err != nil {
		t.Fatalf("store operational state report: %v", err)
	}
	var activeState string
	if err := db.QueryRowContext(ctx, `SELECT active_state FROM monitored_services WHERE host_id='persisted-host' AND service_name='web.service'`).Scan(&activeState); err != nil || activeState != "active" {
		t.Fatalf("monitored service state = %q, err=%v", activeState, err)
	}
	var heartbeatVersion string
	var policyVersion int64
	if err := db.QueryRowContext(ctx, `SELECT agent_version FROM agent_heartbeats WHERE host_id='persisted-host'`).Scan(&heartbeatVersion); err != nil || heartbeatVersion != "test-version" {
		t.Fatalf("heartbeat agent version = %q, err=%v", heartbeatVersion, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT policy_version FROM host_configuration_versions WHERE host_id='persisted-host'`).Scan(&policyVersion); err != nil || policyVersion != 7 {
		t.Fatalf("policy version = %q, err=%v", policyVersion, err)
	}

	staleReport := serviceReport
	staleReport.CollectedAt = collectedAt.Add(-time.Minute)
	staleReport.PolicyVersion = 3
	staleReport.Services = []agent.ServiceState{{Name: "web.service", ActiveState: "failed", SubState: "failed"}}
	staleReport.Recoveries = []agent.RecoveryExecution{{Policy: "web-restart", Service: "web.service", StartedAt: collectedAt.Add(-2 * time.Minute), FinishedAt: collectedAt.Add(-time.Minute), Outcome: "succeeded", Verified: true}}
	if err := api.storeReport(ctx, "persisted-host", "delayed-report", staleReport); err != nil {
		t.Fatalf("store delayed recovery report: %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT active_state FROM monitored_services WHERE host_id='persisted-host' AND service_name='web.service'`).Scan(&activeState); err != nil || activeState != "active" {
		t.Fatalf("stale report changed monitored state to %q, err=%v", activeState, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT policy_version FROM host_configuration_versions WHERE host_id='persisted-host'`).Scan(&policyVersion); err != nil || policyVersion != 7 {
		t.Fatalf("stale report changed policy version to %q, err=%v", policyVersion, err)
	}
	var recoveryCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM recovery_executions WHERE host_id='persisted-host'`).Scan(&recoveryCount); err != nil || recoveryCount != 1 {
		t.Fatalf("persisted delayed recoveries = %d, err=%v", recoveryCount, err)
	}

	notificationReport := serviceReport
	notificationReport.CollectedAt = collectedAt.Add(time.Minute)
	notificationReport.Alerts = []agent.Alert{{Metric: "cpu", Message: "sustained CPU threshold"}}
	if err := api.storeReport(ctx, "persisted-host", "report-2", notificationReport); err != nil {
		t.Fatalf("store report that opens incident: %v", err)
	}
	var notificationCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM notifications WHERE host_id='persisted-host' AND channel='dashboard'`).Scan(&notificationCount); err != nil || notificationCount != 1 {
		t.Fatalf("dashboard notification rows = %d, err=%v", notificationCount, err)
	}
	activeReq := httptest.NewRequest(http.MethodGet, "/api/v1/incidents?status=active&limit=20", nil)
	activeReq.Header.Set("Authorization", "Bearer "+adminToken)
	activeRes := httptest.NewRecorder()
	handler.ServeHTTP(activeRes, activeReq)
	if activeRes.Code != http.StatusOK || !strings.Contains(activeRes.Body.String(), "persisted-host") {
		t.Fatalf("active incident filter status=%d body=%s", activeRes.Code, activeRes.Body.String())
	}

	prometheus := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query_range" || r.URL.Query().Get("query") != `hostsentry_agent_cpu_usage_percent{host_id="persisted-host"}` || r.URL.Query().Get("step") != "30" {
			t.Errorf("unexpected Prometheus range query: %s", r.URL.String())
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"host_id":"persisted-host"},"values":[[1794320000,"17.5"]]}]}}`))
	}))
	defer prometheus.Close()
	if err := api.SetPrometheusURL(prometheus.URL); err != nil {
		t.Fatalf("set test Prometheus URL: %v", err)
	}
	historyReq := httptest.NewRequest(http.MethodGet, "/api/v1/hosts/persisted-host/metrics?metric=cpu&range=1h", nil)
	historyReq.Header.Set("Authorization", "Bearer "+adminToken)
	historyRes := httptest.NewRecorder()
	handler.ServeHTTP(historyRes, historyReq)
	if historyRes.Code != http.StatusOK || !strings.Contains(historyRes.Body.String(), `"value":17.5`) {
		t.Fatalf("metric history status=%d body=%s", historyRes.Code, historyRes.Body.String())
	}
}

func testAgentMTLSIngestion(t *testing.T, ctx context.Context, db *sql.DB, api *API) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Millisecond)
	caCert, caKey := integrationTestCA(t, now)
	serverPair, _ := integrationTestLeaf(t, caCert, caKey, now, 2, "localhost", x509.ExtKeyUsageServerAuth, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	clientPair, _ := integrationTestLeaf(t, caCert, caKey, now, 3, "agent-mtls", x509.ExtKeyUsageClientAuth, nil, nil)
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(caCert)

	server := httptest.NewUnstartedServer(api.Handler())
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverPair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	}
	server.StartTLS()
	defer server.Close()

	directory := t.TempDir()
	caPath := filepath.Join(directory, "ca.crt")
	clientCertPath := filepath.Join(directory, "agent.crt")
	clientKeyPath := filepath.Join(directory, "agent.key")
	queuePath := filepath.Join(directory, "queue.jsonl")
	writeIntegrationPEM(t, caPath, "CERTIFICATE", caCert.Raw, 0o644)
	writeIntegrationPEM(t, clientCertPath, "CERTIFICATE", clientPair.Certificate[0], 0o600)
	clientKeyDER, err := x509.MarshalPKCS8PrivateKey(clientPair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	writeIntegrationPEM(t, clientKeyPath, "PRIVATE KEY", clientKeyDER, 0o600)
	reporter, err := agent.NewRemoteReporter(agent.CentralConfig{
		URL: server.URL, AgentID: "agent-mtls", CACertificate: caPath,
		ClientCert: clientCertPath, ClientKey: clientKeyPath,
		QueuePath: queuePath, QueueMaxBytes: 1 << 20, RequestTimeout: agent.Duration(5 * time.Second),
	})
	if err != nil {
		t.Fatalf("create remote reporter: %v", err)
	}
	started := now.Add(-time.Minute)
	report := agent.Report{
		SchemaVersion: "1", CollectedAt: now,
		System:   agent.System{Hostname: "integration-arch", Distribution: "arch", AgentVersion: "integration-test"},
		CPU:      agent.CPU{UsagePercent: 21.5},
		Services: []agent.ServiceState{{Name: "web.service", LoadState: "loaded", ActiveState: "active", SubState: "running", MainPID: 42}},
		Recoveries: []agent.RecoveryExecution{{
			Policy: "web-restart", Service: "web.service", StartedAt: started,
			FinishedAt: now, Outcome: "succeeded", Verified: true,
		}},
	}
	if err := reporter.Enqueue(report); err != nil {
		t.Fatalf("enqueue agent report: %v", err)
	}
	if err := reporter.Flush(ctx); err != nil {
		t.Fatalf("deliver agent report over mutual TLS: %v", err)
	}
	trustedRoots := x509.NewCertPool()
	trustedRoots.AddCert(caCert)
	identityClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS12, RootCAs: trustedRoots, Certificates: []tls.Certificate{clientPair},
	}}}
	identityRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/api/v1/agent/reports", strings.NewReader(`{"id":"wrong-agent:report","report":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	identityRequest.Header.Set("Content-Type", "application/json")
	identityRequest.Header.Set("X-HostSentry-Agent", "wrong-agent")
	identityResponse, err := identityClient.Do(identityRequest)
	if err != nil {
		t.Fatalf("send mismatched agent identity: %v", err)
	}
	_ = identityResponse.Body.Close()
	identityClient.CloseIdleConnections()
	if identityResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("mismatched certificate identity status=%d, want 401", identityResponse.StatusCode)
	}
	var hostCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM hosts WHERE id='agent-mtls' AND hostname='integration-arch' AND latest_report->'cpu'->>'usage_percent'='21.5'`).Scan(&hostCount); err != nil || hostCount != 1 {
		t.Fatalf("mTLS report was not persisted: rows=%d err=%v", hostCount, err)
	}
	var serviceCount, recoveryCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM monitored_services WHERE host_id='agent-mtls' AND service_name='web.service' AND active_state='active'`).Scan(&serviceCount); err != nil || serviceCount != 1 {
		t.Fatalf("mTLS service state was not persisted: rows=%d err=%v", serviceCount, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM recovery_executions WHERE host_id='agent-mtls' AND policy='web-restart' AND verified`).Scan(&recoveryCount); err != nil || recoveryCount != 1 {
		t.Fatalf("mTLS recovery result was not persisted: rows=%d err=%v", recoveryCount, err)
	}
	if err := reporter.Enqueue(report); err != nil {
		t.Fatalf("enqueue duplicate report: %v", err)
	}
	if err := reporter.Flush(ctx); err != nil {
		t.Fatalf("deliver duplicate report: %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM hosts WHERE id='agent-mtls'`).Scan(&hostCount); err != nil || hostCount != 1 {
		t.Fatalf("duplicate report created another host row: rows=%d err=%v", hostCount, err)
	}
}

func integrationTestCA(t *testing.T, now time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "HostSentry Integration CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key
}

func integrationTestLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, now time.Time, serial int64, commonName string, usage x509.ExtKeyUsage, dnsNames []string, ips []net.IP) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: commonName},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
		DNSNames: dnsNames, IPAddresses: ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER}))
	if err != nil {
		t.Fatal(err)
	}
	return pair, certificate
}

func writeIntegrationPEM(t *testing.T, path, blockType string, data []byte, mode os.FileMode) {
	t.Helper()
	content := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: data})
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatal(err)
	}
}
