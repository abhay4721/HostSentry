package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRemoteReporterRetriesQueuedReportWithMutualTLS(t *testing.T) {
	caCert, caKey := testCertificateAuthority(t)
	serverPair, serverCert := testLeafCertificate(t, caCert, caKey, "localhost", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, x509.ExtKeyUsageServerAuth)
	clientPair, _ := testLeafCertificate(t, caCert, caKey, "agent-1", nil, nil, x509.ExtKeyUsageClientAuth)
	clientCA := x509.NewCertPool()
	clientCA.AddCert(caCert)
	var fail atomic.Bool
	fail.Store(true)
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/agent/reports" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("X-HostSentry-Agent") != "agent-1" || r.Header.Get("Idempotency-Key") == "" {
			t.Errorf("agent identity or idempotency header missing")
		}
		if r.TLS == nil || len(r.TLS.PeerCertificates) != 1 || r.TLS.PeerCertificates[0].Subject.CommonName != "agent-1" {
			t.Errorf("client certificate identity was not presented")
		}
		var item queuedReport
		if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
			t.Errorf("decode queued report: %v", err)
		} else if len(item.Report.Recoveries) != 1 || !item.Report.Recoveries[0].Verified {
			t.Errorf("queued recovery event was not preserved: %+v", item.Report.Recoveries)
		}
		if fail.Load() {
			http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverPair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCA,
		MinVersion:   tls.VersionTLS12,
	}
	server.StartTLS()
	defer server.Close()
	if err := serverCert.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("test server certificate is not signed by test CA: %v", err)
	}

	directory := t.TempDir()
	caPath := filepath.Join(directory, "ca.pem")
	clientCertPath := filepath.Join(directory, "agent.crt")
	clientKeyPath := filepath.Join(directory, "agent.key")
	queuePath := filepath.Join(directory, "queue.jsonl")
	writeCertificate(t, caPath, caCert)
	writeTLSKeyPair(t, clientCertPath, clientKeyPath, clientPair)
	cfg := CentralConfig{
		URL: server.URL, AgentID: "agent-1", CACertificate: caPath,
		ClientCert: clientCertPath, ClientKey: clientKeyPath,
		QueuePath: queuePath, QueueMaxBytes: 1 << 20, RequestTimeout: Duration(5 * time.Second),
	}

	now := time.Now().UTC()
	report := Report{
		CollectedAt: now,
		System:      System{Hostname: "test-host", AgentVersion: "test"},
		Recoveries:  []RecoveryExecution{{Policy: "restart-web", Service: "web.service", StartedAt: now.Add(-time.Second), FinishedAt: now, Outcome: "succeeded", Verified: true}},
	}
	first, err := NewRemoteReporter(cfg)
	if err != nil {
		t.Fatalf("create first reporter: %v", err)
	}
	if err := first.Enqueue(report); err != nil {
		t.Fatalf("enqueue report: %v", err)
	}
	if err := first.Flush(context.Background()); err == nil || !strings.Contains(err.Error(), "HTTP 503") {
		t.Fatalf("first delivery error = %v, want HTTP 503", err)
	}
	if _, ok, err := first.queue.Peek(); err != nil || !ok {
		t.Fatalf("failed report was not retained: ok=%v err=%v", ok, err)
	}

	// A fresh reporter simulates an agent process restart with the same durable queue.
	second, err := NewRemoteReporter(cfg)
	if err != nil {
		t.Fatalf("create reporter after restart: %v", err)
	}
	fail.Store(false)
	if err := second.Flush(context.Background()); err != nil {
		t.Fatalf("retry after restart: %v", err)
	}
	if _, ok, err := second.queue.Peek(); err != nil || ok {
		t.Fatalf("delivered report remains queued: ok=%v err=%v", ok, err)
	}
	if requests.Load() != 2 {
		t.Fatalf("requests = %d, want one failure and one retry", requests.Load())
	}
}

func testCertificateAuthority(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "HostSentry test CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
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

func testLeafCertificate(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, commonName string, dnsNames []string, ips []net.IP, usage x509.ExtKeyUsage) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: commonName},
		DNSNames: dnsNames, IPAddresses: ips,
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{usage},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, certificate
}

func writeCertificate(t *testing.T, path string, certificate *x509.Certificate) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeTLSKeyPair(t *testing.T, certPath, keyPath string, pair tls.Certificate) {
	t.Helper()
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]}), 0o600); err != nil {
		t.Fatal(err)
	}
	key, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("unexpected private key type %T", pair.PrivateKey)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}
