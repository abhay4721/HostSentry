package server

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"embed"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hostsentry/hostsentry/internal/agent"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

type API struct {
	db              *sql.DB
	metricsToken    string
	prometheusURL   string
	notifier        *Notifier
	healthWeights   agent.HealthWeights
	recoveryEnabled bool
	recoveryDryRun  bool
	anomaly         AnomalySettings
}

type AnomalySettings struct {
	Enabled        bool
	MinimumSamples int64
	Sigma          float64
}

func DefaultAnomalySettings() AnomalySettings {
	return AnomalySettings{Enabled: true, MinimumSamples: 20, Sigma: 3}
}

func NewAPI(db *sql.DB, metricsToken string, healthWeights agent.HealthWeights, recoveryEnabled, recoveryDryRun bool, anomaly AnomalySettings) *API {
	return &API{db: db, metricsToken: metricsToken, healthWeights: healthWeights, recoveryEnabled: recoveryEnabled, recoveryDryRun: recoveryDryRun, anomaly: anomaly}
}

func (a *API) SetNotifier(notifier *Notifier) { a.notifier = notifier }

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.health)
	mux.HandleFunc("GET /metrics", a.requireToken(a.metricsToken, a.metrics))
	mux.HandleFunc("POST /api/v1/auth/login", a.login)
	mux.HandleFunc("GET /api/v1/auth/me", a.requireUser(a.currentUser))
	mux.HandleFunc("POST /api/v1/auth/logout", a.requireUser(a.logout))
	mux.HandleFunc("GET /api/v1/users", a.requireAdmin(a.listUsers))
	mux.HandleFunc("POST /api/v1/users", a.requireAdmin(a.createUser))
	mux.HandleFunc("PATCH /api/v1/users/{id}", a.requireAdmin(a.updateUser))
	mux.HandleFunc("GET /api/v1/overview", a.requireUser(a.overview))
	mux.HandleFunc("GET /api/v1/notifications", a.requireUser(a.listNotifications))
	mux.HandleFunc("GET /api/v1/reports/hosts.csv", a.requireUser(a.exportHostsCSV))
	mux.HandleFunc("GET /api/v1/settings", a.requireUser(a.settings))
	mux.HandleFunc("POST /api/v1/agent/reports", a.ingestReport)
	mux.HandleFunc("GET /api/v1/agent/policies", a.agentPolicies)
	mux.HandleFunc("GET /api/v1/hosts", a.requireUser(a.listHosts))
	mux.HandleFunc("GET /api/v1/hosts/{id}", a.requireUser(a.getHost))
	mux.HandleFunc("GET /api/v1/hosts/{id}/metrics", a.requireUser(a.hostMetricHistory))
	mux.HandleFunc("GET /api/v1/incidents", a.requireUser(a.listIncidents))
	mux.HandleFunc("GET /api/v1/incidents/{id}/events", a.requireUser(a.listIncidentEvents))
	mux.HandleFunc("PATCH /api/v1/incidents/{id}", a.requireOperator(a.updateIncident))
	mux.HandleFunc("GET /api/v1/recoveries", a.requireUser(a.listRecoveries))
	mux.HandleFunc("GET /api/v1/policies", a.requireUser(a.listPolicies))
	mux.HandleFunc("POST /api/v1/policies", a.requireAdmin(a.createPolicy))
	mux.HandleFunc("PUT /api/v1/policies/{id}", a.requireAdmin(a.updatePolicy))
	mux.HandleFunc("DELETE /api/v1/policies/{id}", a.requireAdmin(a.disablePolicy))
	mux.HandleFunc("POST /api/v1/agents/revoke-certificate", a.requireAdmin(a.revokeCertificate))
	mux.HandleFunc("GET /api/v1/groups", a.requireUser(a.listGroups))
	mux.HandleFunc("POST /api/v1/groups", a.requireAdmin(a.createGroup))
	mux.HandleFunc("PUT /api/v1/groups/{id}", a.requireAdmin(a.updateGroup))
	mux.HandleFunc("DELETE /api/v1/groups/{id}", a.requireAdmin(a.deleteGroup))
	return mux
}

type overviewStats struct {
	TotalHosts           int `json:"total_hosts"`
	OnlineHosts          int `json:"online_hosts"`
	HealthyHosts         int `json:"healthy_hosts"`
	CriticalHosts        int `json:"critical_hosts"`
	ActiveIncidents      int `json:"active_incidents"`
	SuccessfulRecoveries int `json:"successful_recoveries"`
}

func (a *API) listNotifications(w http.ResponseWriter, r *http.Request) {
	limit, offset, ok := pagination(w, r)
	if !ok {
		return
	}
	rows, err := a.db.QueryContext(r.Context(), `SELECT n.id,n.host_id,n.severity,n.message,i.status,n.created_at,i.last_seen
		FROM notifications n JOIN incidents i ON i.id=n.incident_id
		ORDER BY n.created_at DESC,n.id DESC LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query_failed", "notifications could not be loaded")
		return
	}
	defer rows.Close()
	type notification struct {
		ID        int64     `json:"id"`
		HostID    string    `json:"host_id"`
		Severity  string    `json:"severity"`
		Message   string    `json:"message"`
		Status    string    `json:"status"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
	}
	items := make([]notification, 0)
	for rows.Next() {
		var n notification
		if err := rows.Scan(&n.ID, &n.HostID, &n.Severity, &n.Message, &n.Status, &n.CreatedAt, &n.UpdatedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "query_failed", "notifications could not be loaded")
			return
		}
		items = append(items, n)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "query_failed", "notifications could not be loaded")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "limit": limit, "offset": offset})
}

func (a *API) exportHostsCSV(w http.ResponseWriter, r *http.Request) {
	rows, err := a.db.QueryContext(r.Context(), `SELECT h.id,h.hostname,h.distribution,h.distribution_version,h.kernel_version,h.architecture,h.agent_version,h.first_seen,h.last_seen,COALESCE((h.latest_report#>>'{cpu,usage_percent}')::double precision,0),COALESCE((h.latest_report#>>'{memory,usage_percent}')::double precision,0),(SELECT count(*) FROM incidents i WHERE i.host_id=h.id AND i.resolved_at IS NULL) FROM hosts h ORDER BY h.hostname,h.id`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query_failed", "host report could not be generated")
		return
	}
	defer rows.Close()
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=hostsentry-hosts.csv")
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"host_id", "hostname", "distribution", "distribution_version", "kernel_version", "architecture", "agent_version", "first_seen_utc", "last_seen_utc", "online", "cpu_usage_percent", "memory_usage_percent", "open_incidents"}); err != nil {
		return
	}
	for rows.Next() {
		var id, hostname, distro, distroVersion, kernel, arch, version string
		var first, last time.Time
		var cpu, memory float64
		var incidents int
		if err := rows.Scan(&id, &hostname, &distro, &distroVersion, &kernel, &arch, &version, &first, &last, &cpu, &memory, &incidents); err != nil {
			return
		}
		online := time.Since(last) < 90*time.Second
		record := []string{id, hostname, distro, distroVersion, kernel, arch, version, first.UTC().Format(time.RFC3339), last.UTC().Format(time.RFC3339), strconv.FormatBool(online), strconv.FormatFloat(cpu, 'f', 2, 64), strconv.FormatFloat(memory, 'f', 2, 64), strconv.Itoa(incidents)}
		if err := cw.Write(record); err != nil {
			return
		}
	}
	cw.Flush()
}

func (a *API) settings(w http.ResponseWriter, r *http.Request) {
	channels := []string{}
	if a.notifier != nil {
		channels = a.notifier.EnabledChannels()
	}
	writeJSON(w, http.StatusOK, map[string]any{"health_weights": a.healthWeights, "recovery_enabled": a.recoveryEnabled, "recovery_dry_run": a.recoveryDryRun, "anomaly_detection_enabled": a.anomaly.Enabled, "anomaly_minimum_samples": a.anomaly.MinimumSamples, "anomaly_sigma": a.anomaly.Sigma, "agent_offline_after_seconds": 90, "policy_action_types": []string{"restart_service"}, "notification_channels": channels})
}

func (a *API) overview(w http.ResponseWriter, r *http.Request) {
	var stats overviewStats
	err := a.db.QueryRowContext(r.Context(), `SELECT
		(SELECT count(*) FROM hosts),
		(SELECT count(*) FROM hosts WHERE last_seen > now()-interval '90 seconds'),
		(SELECT count(*) FROM hosts h WHERE h.last_seen > now()-interval '90 seconds' AND NOT EXISTS (SELECT 1 FROM incidents i WHERE i.host_id=h.id AND i.resolved_at IS NULL)),
		(SELECT count(DISTINCT host_id) FROM incidents WHERE resolved_at IS NULL AND severity='critical'),
		(SELECT count(*) FROM incidents WHERE resolved_at IS NULL),
		(SELECT count(*) FROM recovery_executions WHERE outcome='succeeded' AND verified)`).Scan(&stats.TotalHosts, &stats.OnlineHosts, &stats.HealthyHosts, &stats.CriticalHosts, &stats.ActiveIncidents, &stats.SuccessfulRecoveries)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query_failed", "fleet summary could not be loaded")
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func Migrate(ctx context.Context, db *sql.DB) error {
	migrations, err := migrationFiles.ReadDir("migrations")
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin database migration: %w", err)
	}
	defer tx.Rollback()
	for _, migration := range migrations {
		if migration.IsDir() || !strings.HasSuffix(migration.Name(), ".sql") {
			continue
		}
		data, err := migrationFiles.ReadFile("migrations/" + migration.Name())
		if err != nil {
			return fmt.Errorf("read database migration %s: %w", migration.Name(), err)
		}
		for _, statement := range strings.Split(string(data), ";") {
			statement = strings.TrimSpace(statement)
			if statement == "" {
				continue
			}
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("apply database migration %s: %w", migration.Name(), err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit database migration: %w", err)
	}
	return nil
}

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := a.db.PingContext(ctx); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database_unavailable", "database health check failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *API) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return a.requireRole(next, "admin")
}

func (a *API) requireOperator(next http.HandlerFunc) http.HandlerFunc {
	return a.requireRole(next, "admin", "operator")
}

func (a *API) requireUser(next http.HandlerFunc) http.HandlerFunc {
	return a.requireRole(next, "admin", "operator", "viewer")
}

func (a *API) requireRole(next http.HandlerFunc, roles ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			writeError(w, http.StatusUnauthorized, "unauthorized", "login required")
			return
		}
		user, err := a.authenticate(r.Context(), token)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) || errors.Is(err, errInvalidSession) {
				writeError(w, http.StatusUnauthorized, "unauthorized", "session is invalid or expired")
			} else {
				writeError(w, http.StatusServiceUnavailable, "auth_unavailable", "authentication is temporarily unavailable")
			}
			return
		}
		for _, role := range roles {
			if user.Role == role {
				next(w, r.WithContext(context.WithValue(r.Context(), userContextKey{}, user)))
				return
			}
		}
		writeError(w, http.StatusForbidden, "forbidden", "your role cannot perform this action")
	}
}

func (a *API) requireToken(expected string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if expected == "" {
			writeError(w, http.StatusServiceUnavailable, "auth_unconfigured", "API token is not configured")
			return
		}
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			writeError(w, http.StatusUnauthorized, "unauthorized", "valid bearer token required")
			return
		}
		token := strings.TrimPrefix(header, "Bearer ")
		if len(token) != len(expected) || subtle.ConstantTimeCompare([]byte(token), []byte(expected)) != 1 {
			writeError(w, http.StatusUnauthorized, "unauthorized", "valid bearer token required")
			return
		}
		next(w, r)
	}
}

func (a *API) ingestReport(w http.ResponseWriter, r *http.Request) {
	identity, ok := a.agentIdentity(w, r)
	if !ok {
		return
	}
	var payload struct {
		ID     string       `json:"id"`
		Report agent.Report `json:"report"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20))
	if err := decoder.Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "report payload is invalid or too large")
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid_json", "request must contain one JSON object")
		return
	}
	if payload.ID == "" || len(payload.ID) > 256 || payload.Report.CollectedAt.IsZero() || payload.Report.System.Hostname == "" || payload.Report.CollectedAt.After(time.Now().Add(5*time.Minute)) {
		writeError(w, http.StatusBadRequest, "invalid_report", "report id, collection timestamp, and hostname are required")
		return
	}
	if err := a.storeReport(r.Context(), identity, payload.ID, payload.Report); err != nil {
		writeError(w, http.StatusInternalServerError, "storage_failed", "report could not be stored")
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (a *API) storeReport(ctx context.Context, hostID, reportID string, report agent.Report) error {
	encoded, err := json.Marshal(report)
	if err != nil {
		return err
	}
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	receivedAt := time.Now().UTC()
	var latestTime time.Time
	var latestID string
	lookupErr := tx.QueryRowContext(ctx, `SELECT report_collected_at,last_report_id FROM hosts WHERE id=$1 FOR UPDATE`, hostID).Scan(&latestTime, &latestID)
	if lookupErr != nil && !errors.Is(lookupErr, sql.ErrNoRows) {
		return lookupErr
	}
	if lookupErr == nil && (report.CollectedAt.Before(latestTime) || reportID == latestID) {
		if err := insertRecoveries(ctx, tx, hostID, report.Recoveries); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE hosts SET last_seen=$2 WHERE id=$1`, hostID, receivedAt); err != nil {
			return err
		}
		if err := upsertAgentOperationalState(ctx, tx, hostID, reportID, report, receivedAt, false); err != nil {
			return err
		}
		return tx.Commit()
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO hosts
		(id,hostname,os,distribution,distribution_version,kernel_version,architecture,agent_version,last_seen,report_collected_at,last_report_id,latest_report)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb)
		ON CONFLICT (id) DO UPDATE SET hostname=EXCLUDED.hostname,os=EXCLUDED.os,
		distribution=EXCLUDED.distribution,distribution_version=EXCLUDED.distribution_version,
		kernel_version=EXCLUDED.kernel_version,architecture=EXCLUDED.architecture,
		agent_version=EXCLUDED.agent_version,last_seen=EXCLUDED.last_seen,
		report_collected_at=EXCLUDED.report_collected_at,last_report_id=EXCLUDED.last_report_id,latest_report=EXCLUDED.latest_report
		WHERE hosts.report_collected_at <= EXCLUDED.report_collected_at`,
		hostID, report.System.Hostname, report.System.OS, report.System.Distribution,
		report.System.DistributionVersion, report.System.KernelVersion, report.System.Architecture,
		report.System.AgentVersion, receivedAt, report.CollectedAt, reportID, string(encoded))
	if err != nil {
		return err
	}
	rowsChanged, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsChanged == 0 {
		if err := insertRecoveries(ctx, tx, hostID, report.Recoveries); err != nil {
			return err
		}
		if err := upsertAgentOperationalState(ctx, tx, hostID, reportID, report, receivedAt, false); err != nil {
			return err
		}
		return tx.Commit() // Ignore delayed replays that would move host state backwards.
	}
	if err := upsertAgentOperationalState(ctx, tx, hostID, reportID, report, receivedAt, true); err != nil {
		return err
	}
	newNotifications := make([]IncidentNotification, 0)
	active := make(map[string]incidentInput)
	for _, alert := range report.Alerts {
		key := "metric:" + alert.Metric
		active[key] = incidentInput{fingerprint: key, incidentType: "resource_threshold", severity: "warning", description: alert.Message}
	}
	for _, service := range report.Services {
		if service.ActiveState == "active" {
			continue
		}
		key := "service:" + service.Name
		active[key] = incidentInput{fingerprint: key, incidentType: "systemd_service_failed", severity: "critical", description: fmt.Sprintf("service %s is %s/%s", service.Name, service.ActiveState, service.SubState)}
	}
	if a.anomaly.Enabled {
		anomalies, err := a.updateBaselinesAndDetect(ctx, tx, hostID, report, receivedAt)
		if err != nil {
			return err
		}
		for _, incident := range anomalies {
			active[incident.fingerprint] = incident
		}
	}
	fingerprints := make([]string, 0, len(active))
	for _, incident := range active {
		fingerprints = append(fingerprints, incident.fingerprint)
		var inserted bool
		var incidentID int64
		err = tx.QueryRowContext(ctx, `INSERT INTO incidents (host_id,fingerprint,incident_type,severity,description,first_seen,last_seen)
			VALUES ($1,$2,$3,$4,$5,$6,$6)
			ON CONFLICT (host_id,fingerprint) WHERE resolved_at IS NULL
			DO UPDATE SET severity=EXCLUDED.severity,description=EXCLUDED.description,last_seen=EXCLUDED.last_seen
			RETURNING id,(xmax=0)`, hostID, incident.fingerprint, incident.incidentType, incident.severity, incident.description, receivedAt).Scan(&incidentID, &inserted)
		if err != nil {
			return err
		}
		if inserted {
			newNotifications = append(newNotifications, IncidentNotification{HostID: hostID, Type: incident.incidentType, Severity: incident.severity, Description: incident.description, DetectedAt: receivedAt})
			if _, err := tx.ExecContext(ctx, `INSERT INTO notifications(incident_id,host_id,channel,severity,message,created_at) VALUES($1,$2,'dashboard',$3,$4,$5) ON CONFLICT (incident_id,channel) DO NOTHING`, incidentID, hostID, incident.severity, incident.description, receivedAt); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO incident_events(incident_id,event_type,actor,details) VALUES($1,'opened','agent',jsonb_build_object('severity',$2::text,'description',$3::text))`, incidentID, incident.severity, incident.description); err != nil {
				return err
			}
		}
	}
	preserve := incompleteFingerprints(report.Warnings)
	resolvedRows, err := tx.QueryContext(ctx, `UPDATE incidents SET status='resolved',resolved_at=$2,last_seen=$2
		WHERE host_id=$1 AND resolved_at IS NULL AND NOT (fingerprint = ANY($3::text[]))
		AND NOT EXISTS (SELECT 1 FROM unnest($4::text[]) AS pattern WHERE incidents.fingerprint LIKE pattern) RETURNING id`, hostID, receivedAt, fingerprints, preserve)
	if err != nil {
		return err
	}
	resolvedIDs := make([]int64, 0)
	for resolvedRows.Next() {
		var id int64
		if err := resolvedRows.Scan(&id); err != nil {
			resolvedRows.Close()
			return err
		}
		resolvedIDs = append(resolvedIDs, id)
	}
	if err := resolvedRows.Err(); err != nil {
		resolvedRows.Close()
		return err
	}
	resolvedRows.Close()
	for _, id := range resolvedIDs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO incident_events(incident_id,event_type,actor,details) VALUES($1,'resolved','agent','{}'::jsonb)`, id); err != nil {
			return err
		}
	}
	if err := insertRecoveries(ctx, tx, hostID, report.Recoveries); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if a.notifier != nil {
		for _, event := range newNotifications {
			notifyCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			a.notifier.Notify(notifyCtx, event)
			cancel()
		}
	}
	return nil
}

func upsertAgentOperationalState(ctx context.Context, tx *sql.Tx, hostID, reportID string, report agent.Report, receivedAt time.Time, complete bool) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO agent_heartbeats(host_id,received_at,report_collected_at,report_id,agent_version,warning_count)
		VALUES($1,$2,$3,$4,$5,$6)
		ON CONFLICT(host_id) DO UPDATE SET received_at=EXCLUDED.received_at,
		report_collected_at=GREATEST(agent_heartbeats.report_collected_at,EXCLUDED.report_collected_at),
		report_id=CASE WHEN EXCLUDED.report_collected_at>=agent_heartbeats.report_collected_at THEN EXCLUDED.report_id ELSE agent_heartbeats.report_id END,
		agent_version=CASE WHEN EXCLUDED.report_collected_at>=agent_heartbeats.report_collected_at THEN EXCLUDED.agent_version ELSE agent_heartbeats.agent_version END,
		warning_count=CASE WHEN EXCLUDED.report_collected_at>=agent_heartbeats.report_collected_at THEN EXCLUDED.warning_count ELSE agent_heartbeats.warning_count END`,
		hostID, receivedAt, report.CollectedAt, reportID, report.System.AgentVersion, len(report.Warnings))
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO host_configuration_versions(host_id,policy_version,observed_at) VALUES($1,$2,$3)
		ON CONFLICT(host_id) DO UPDATE SET policy_version=EXCLUDED.policy_version,observed_at=EXCLUDED.observed_at
		WHERE host_configuration_versions.observed_at<=EXCLUDED.observed_at`, hostID, report.PolicyVersion, report.CollectedAt)
	if err != nil {
		return err
	}
	if !complete || warningFor(report.Warnings, "systemd services") {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM monitored_services WHERE host_id=$1`, hostID); err != nil {
		return err
	}
	for _, service := range report.Services {
		var activeSince any
		if !service.Since.IsZero() {
			activeSince = service.Since
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO monitored_services
			(host_id,service_name,load_state,active_state,sub_state,main_pid,last_result,restart_count,active_since,observed_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			hostID, service.Name, service.LoadState, service.ActiveState, service.SubState, service.MainPID, service.Result, service.Restarts, activeSince, report.CollectedAt); err != nil {
			return err
		}
	}
	return nil
}

func insertRecoveries(ctx context.Context, tx *sql.Tx, hostID string, recoveries []agent.RecoveryExecution) error {
	for _, recovery := range recoveries {
		_, err := tx.ExecContext(ctx, `INSERT INTO recovery_executions
			(host_id,policy,service,started_at,finished_at,outcome,verified,error)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (host_id,policy,started_at) DO NOTHING`,
			hostID, recovery.Policy, recovery.Service, recovery.StartedAt, recovery.FinishedAt, recovery.Outcome, recovery.Verified, recovery.Error)
		if err != nil {
			return err
		}
	}
	return nil
}

func incompleteFingerprints(warnings []string) []string {
	var patterns []string
	if warningFor(warnings, "cpu utilization") {
		patterns = append(patterns, "metric:cpu%", "anomaly:cpu")
	}
	if warningFor(warnings, "memory") {
		patterns = append(patterns, "metric:memory%", "anomaly:memory")
	}
	if warningFor(warnings, "filesystem") {
		patterns = append(patterns, "metric:disk:%", "anomaly:disk:%")
	}
	if warningFor(warnings, "systemd services") {
		patterns = append(patterns, "service:%")
	}
	return patterns
}

type incidentInput struct {
	fingerprint  string
	incidentType string
	severity     string
	description  string
}

type hostSummary struct {
	ID               string          `json:"id"`
	Hostname         string          `json:"hostname"`
	OS               string          `json:"os"`
	Distribution     string          `json:"distribution"`
	Kernel           string          `json:"kernel_version"`
	Architecture     string          `json:"architecture"`
	AgentVersion     string          `json:"agent_version"`
	PolicyVersion    int64           `json:"policy_version"`
	LastSeen         time.Time       `json:"last_seen"`
	Online           bool            `json:"online"`
	CPUUsage         float64         `json:"cpu_usage_percent"`
	MemoryUsage      float64         `json:"memory_usage_percent"`
	OpenIncidents    int             `json:"open_incidents"`
	HealthScore      int             `json:"health_score"`
	HealthComponents map[string]int  `json:"health_components,omitempty"`
	Report           json.RawMessage `json:"report,omitempty"`
}

func (a *API) listHosts(w http.ResponseWriter, r *http.Request) {
	limit, offset, ok := pagination(w, r)
	if !ok {
		return
	}
	includeReport := false
	if raw := r.URL.Query().Get("include_report"); raw != "" {
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_filter", "include_report must be true or false")
			return
		}
		includeReport = parsed
	}
	groupID := r.URL.Query().Get("group_id")
	if groupID != "" && !groupIDPattern.MatchString(groupID) {
		writeError(w, http.StatusBadRequest, "invalid_group_id", "group id filter is invalid")
		return
	}
	var groupFilter any
	if groupID != "" {
		groupFilter = groupID
	}
	rows, err := a.db.QueryContext(r.Context(), `SELECT h.id,h.hostname,h.os,h.distribution,h.kernel_version,h.architecture,h.agent_version,h.last_seen,
		COALESCE((h.latest_report#>>'{cpu,usage_percent}')::double precision,0),
		COALESCE((h.latest_report#>>'{memory,usage_percent}')::double precision,0),
		(SELECT count(*) FROM incidents i WHERE i.host_id=h.id AND i.resolved_at IS NULL),COALESCE(cv.policy_version,0),h.latest_report
		FROM hosts h LEFT JOIN host_configuration_versions cv ON cv.host_id=h.id
		WHERE ($3::uuid IS NULL OR EXISTS (SELECT 1 FROM host_group_members gm WHERE gm.host_id=h.id AND gm.group_id=$3::uuid))
		ORDER BY h.last_seen DESC,h.id LIMIT $1 OFFSET $2`, limit, offset, groupFilter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query_failed", "host list could not be loaded")
		return
	}
	defer rows.Close()
	hosts := make([]hostSummary, 0)
	for rows.Next() {
		var host hostSummary
		var report []byte
		if err := rows.Scan(&host.ID, &host.Hostname, &host.OS, &host.Distribution, &host.Kernel, &host.Architecture, &host.AgentVersion, &host.LastSeen, &host.CPUUsage, &host.MemoryUsage, &host.OpenIncidents, &host.PolicyVersion, &report); err != nil {
			writeError(w, http.StatusInternalServerError, "query_failed", "host list could not be loaded")
			return
		}
		host.Online = time.Since(host.LastSeen) < 90*time.Second
		var snapshot agent.Report
		if json.Unmarshal(report, &snapshot) == nil {
			host.HealthScore, host.HealthComponents = agent.ScoreHealth(snapshot, host.Online, a.healthWeights)
		}
		if includeReport {
			host.Report = json.RawMessage(report)
		}
		hosts = append(hosts, host)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "query_failed", "host list could not be loaded")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": hosts, "limit": limit, "offset": offset})
}

func (a *API) getHost(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validAgentID(id) {
		writeError(w, http.StatusBadRequest, "invalid_host_id", "host id is invalid")
		return
	}
	var host hostSummary
	var report []byte
	err := a.db.QueryRowContext(r.Context(), `SELECT h.id,h.hostname,h.os,h.distribution,h.kernel_version,h.architecture,h.agent_version,h.last_seen,COALESCE(cv.policy_version,0),h.latest_report
		FROM hosts h LEFT JOIN host_configuration_versions cv ON cv.host_id=h.id WHERE h.id=$1`, id).
		Scan(&host.ID, &host.Hostname, &host.OS, &host.Distribution, &host.Kernel, &host.Architecture, &host.AgentVersion, &host.LastSeen, &host.PolicyVersion, &report)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "host_not_found", "host does not exist")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query_failed", "host could not be loaded")
		return
	}
	host.Online = time.Since(host.LastSeen) < 90*time.Second
	host.Report = json.RawMessage(report)
	var snapshot agent.Report
	if json.Unmarshal(report, &snapshot) == nil {
		host.HealthScore, host.HealthComponents = agent.ScoreHealth(snapshot, host.Online, a.healthWeights)
	}
	writeJSON(w, http.StatusOK, host)
}

type incidentRecord struct {
	ID          int64      `json:"id"`
	HostID      string     `json:"host_id"`
	Fingerprint string     `json:"fingerprint"`
	Type        string     `json:"type"`
	Severity    string     `json:"severity"`
	Description string     `json:"description"`
	Status      string     `json:"status"`
	FirstSeen   time.Time  `json:"first_seen"`
	LastSeen    time.Time  `json:"last_seen"`
	ResolvedAt  *time.Time `json:"resolved_at,omitempty"`
}

func (a *API) listIncidents(w http.ResponseWriter, r *http.Request) {
	limit, offset, ok := pagination(w, r)
	if !ok {
		return
	}
	status := r.URL.Query().Get("status")
	if status != "" && status != "active" && !oneOf(status, "open", "acknowledged", "investigating", "recovering", "resolved", "suppressed") {
		writeError(w, http.StatusBadRequest, "invalid_filter", "incident status filter is invalid")
		return
	}
	hostID := r.URL.Query().Get("host_id")
	rows, err := a.db.QueryContext(r.Context(), `SELECT id,host_id,fingerprint,incident_type,severity,description,status,first_seen,last_seen,resolved_at
		FROM incidents WHERE ($1='' OR ($1='active' AND resolved_at IS NULL) OR status=$1) AND ($2='' OR host_id=$2) ORDER BY last_seen DESC,id DESC LIMIT $3 OFFSET $4`, status, hostID, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query_failed", "incident list could not be loaded")
		return
	}
	defer rows.Close()
	items := make([]incidentRecord, 0)
	for rows.Next() {
		var item incidentRecord
		if err := rows.Scan(&item.ID, &item.HostID, &item.Fingerprint, &item.Type, &item.Severity, &item.Description, &item.Status, &item.FirstSeen, &item.LastSeen, &item.ResolvedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "query_failed", "incident list could not be loaded")
			return
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "query_failed", "incident list could not be loaded")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "limit": limit, "offset": offset})
}

func (a *API) updateIncident(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		writeError(w, http.StatusBadRequest, "invalid_incident_id", "incident id is invalid")
		return
	}
	var payload struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "incident update is invalid")
		return
	}
	if !oneOf(payload.Status, "acknowledged", "investigating", "suppressed", "resolved") {
		writeError(w, http.StatusBadRequest, "invalid_status", "status update is invalid")
		return
	}
	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "update_failed", "incident could not be updated")
		return
	}
	defer tx.Rollback()
	var previous string
	if err := tx.QueryRowContext(r.Context(), `SELECT status FROM incidents WHERE id=$1 FOR UPDATE`, id).Scan(&previous); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "incident_not_found", "incident does not exist")
		} else {
			writeError(w, http.StatusInternalServerError, "update_failed", "incident could not be updated")
		}
		return
	}
	if _, err := tx.ExecContext(r.Context(), `UPDATE incidents SET status=$2,resolved_at=CASE WHEN $2='resolved' THEN now() ELSE NULL END WHERE id=$1`, id, payload.Status); err != nil {
		writeError(w, http.StatusInternalServerError, "update_failed", "incident could not be updated")
		return
	}
	actor := currentUser(r).Email
	if _, err := tx.ExecContext(r.Context(), `INSERT INTO incident_events(incident_id,event_type,actor,details) VALUES($1,'status_changed',$2,jsonb_build_object('from',$3::text,'to',$4::text))`, id, actor, previous, payload.Status); err != nil {
		writeError(w, http.StatusInternalServerError, "update_failed", "incident timeline could not be recorded")
		return
	}
	if _, err := tx.ExecContext(r.Context(), `INSERT INTO audit_logs(actor,action,target) VALUES ($1,'incident_status_updated',$2)`, actor, strconv.FormatInt(id, 10)); err != nil {
		writeError(w, http.StatusInternalServerError, "update_failed", "incident audit could not be recorded")
		return
	}
	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "update_failed", "incident could not be updated")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type incidentEvent struct {
	ID         int64           `json:"id"`
	IncidentID int64           `json:"incident_id"`
	Type       string          `json:"event_type"`
	Actor      string          `json:"actor"`
	Details    json.RawMessage `json:"details"`
	CreatedAt  time.Time       `json:"created_at"`
}

func (a *API) listIncidentEvents(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		writeError(w, http.StatusBadRequest, "invalid_incident_id", "incident id is invalid")
		return
	}
	rows, err := a.db.QueryContext(r.Context(), `SELECT id,incident_id,event_type,actor,details,created_at FROM incident_events WHERE incident_id=$1 ORDER BY created_at,id LIMIT 500`, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query_failed", "incident timeline could not be loaded")
		return
	}
	defer rows.Close()
	events := make([]incidentEvent, 0)
	for rows.Next() {
		var event incidentEvent
		var details []byte
		if err := rows.Scan(&event.ID, &event.IncidentID, &event.Type, &event.Actor, &details, &event.CreatedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "query_failed", "incident timeline could not be loaded")
			return
		}
		event.Details = details
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "query_failed", "incident timeline could not be loaded")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": events})
}

type recoveryRecord struct {
	ID         int64     `json:"id"`
	HostID     string    `json:"host_id"`
	Policy     string    `json:"policy"`
	Service    string    `json:"service"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Outcome    string    `json:"outcome"`
	Verified   bool      `json:"verified"`
	Error      string    `json:"error"`
}

func (a *API) listRecoveries(w http.ResponseWriter, r *http.Request) {
	limit, offset, ok := pagination(w, r)
	if !ok {
		return
	}
	rows, err := a.db.QueryContext(r.Context(), `SELECT id,host_id,policy,service,started_at,finished_at,outcome,verified,error FROM recovery_executions ORDER BY started_at DESC,id DESC LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query_failed", "recovery history could not be loaded")
		return
	}
	defer rows.Close()
	items := make([]recoveryRecord, 0)
	for rows.Next() {
		var item recoveryRecord
		if err := rows.Scan(&item.ID, &item.HostID, &item.Policy, &item.Service, &item.StartedAt, &item.FinishedAt, &item.Outcome, &item.Verified, &item.Error); err != nil {
			writeError(w, http.StatusInternalServerError, "query_failed", "recovery history could not be loaded")
			return
		}
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "limit": limit, "offset": offset})
}

func (a *API) metrics(w http.ResponseWriter, r *http.Request) {
	rows, err := a.db.QueryContext(r.Context(), `SELECT h.id,h.last_seen,h.latest_report,COALESCE(cv.policy_version,0)
		FROM hosts h LEFT JOIN host_configuration_versions cv ON cv.host_id=h.id ORDER BY h.id`)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "metrics_unavailable", "metrics query failed")
		return
	}
	defer rows.Close()
	var output strings.Builder
	output.WriteString("# HELP hostsentry_agent_heartbeat_timestamp_seconds Last report timestamp.\n# TYPE hostsentry_agent_heartbeat_timestamp_seconds gauge\n")
	output.WriteString("# HELP hostsentry_agent_cpu_usage_percent Latest CPU utilization.\n# TYPE hostsentry_agent_cpu_usage_percent gauge\n")
	output.WriteString("# HELP hostsentry_agent_memory_usage_percent Latest memory utilization.\n# TYPE hostsentry_agent_memory_usage_percent gauge\n")
	output.WriteString("# HELP hostsentry_agent_memory_usage_bytes Latest used memory in bytes.\n# TYPE hostsentry_agent_memory_usage_bytes gauge\n")
	output.WriteString("# HELP hostsentry_agent_disk_usage_percent Latest filesystem utilization.\n# TYPE hostsentry_agent_disk_usage_percent gauge\n")
	output.WriteString("# HELP hostsentry_agent_uptime_seconds Host uptime in seconds.\n# TYPE hostsentry_agent_uptime_seconds gauge\n")
	output.WriteString("# HELP hostsentry_agent_network_receive_bytes_per_second Network receive rate.\n# TYPE hostsentry_agent_network_receive_bytes_per_second gauge\n")
	output.WriteString("# HELP hostsentry_agent_network_transmit_bytes_per_second Network transmit rate.\n# TYPE hostsentry_agent_network_transmit_bytes_per_second gauge\n")
	output.WriteString("# HELP hostsentry_agent_online Whether the last report is within the online window.\n# TYPE hostsentry_agent_online gauge\n")
	output.WriteString("# HELP hostsentry_agent_policy_version Latest centrally assigned policy version reported by the agent.\n# TYPE hostsentry_agent_policy_version gauge\n")
	for rows.Next() {
		var id string
		var seen time.Time
		var encoded []byte
		var policyVersion int64
		if err := rows.Scan(&id, &seen, &encoded, &policyVersion); err != nil {
			writeError(w, http.StatusServiceUnavailable, "metrics_unavailable", "metrics query failed")
			return
		}
		label := promEscape(id)
		var report agent.Report
		if err := json.Unmarshal(encoded, &report); err != nil {
			writeError(w, http.StatusServiceUnavailable, "metrics_unavailable", "stored report could not be decoded")
			return
		}
		fmt.Fprintf(&output, "hostsentry_agent_heartbeat_timestamp_seconds{host_id=\"%s\"} %d\n", label, seen.Unix())
		fmt.Fprintf(&output, "hostsentry_agent_policy_version{host_id=\"%s\"} %d\n", label, policyVersion)
		online := 0
		if time.Since(seen) < 90*time.Second {
			online = 1
		}
		fmt.Fprintf(&output, "hostsentry_agent_online{host_id=\"%s\"} %d\n", label, online)
		fmt.Fprintf(&output, "hostsentry_agent_cpu_usage_percent{host_id=\"%s\"} %s\n", label, strconv.FormatFloat(report.CPU.UsagePercent, 'f', -1, 64))
		fmt.Fprintf(&output, "hostsentry_agent_memory_usage_percent{host_id=\"%s\"} %s\n", label, strconv.FormatFloat(report.Memory.UsagePercent, 'f', -1, 64))
		fmt.Fprintf(&output, "hostsentry_agent_memory_usage_bytes{host_id=\"%s\"} %d\n", label, report.Memory.UsedBytes)
		fmt.Fprintf(&output, "hostsentry_agent_uptime_seconds{host_id=\"%s\"} %d\n", label, report.System.UptimeSeconds)
		for _, disk := range report.Disks {
			fmt.Fprintf(&output, "hostsentry_agent_disk_usage_percent{host_id=\"%s\",mountpoint=\"%s\"} %s\n", label, promEscape(disk.Mountpoint), strconv.FormatFloat(disk.UsagePercent, 'f', -1, 64))
		}
		for _, network := range report.Network {
			iface := promEscape(network.Name)
			fmt.Fprintf(&output, "hostsentry_agent_network_receive_bytes_per_second{host_id=\"%s\",interface=\"%s\"} %s\n", label, iface, strconv.FormatFloat(network.RXBytesPerSecond, 'f', -1, 64))
			fmt.Fprintf(&output, "hostsentry_agent_network_transmit_bytes_per_second{host_id=\"%s\",interface=\"%s\"} %s\n", label, iface, strconv.FormatFloat(network.TXBytesPerSecond, 'f', -1, 64))
		}
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusServiceUnavailable, "metrics_unavailable", "metrics query failed")
		return
	}
	rows.Close()
	if err := appendCountMetrics(r.Context(), a.db, &output); err != nil {
		writeError(w, http.StatusServiceUnavailable, "metrics_unavailable", "metrics query failed")
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, output.String())
}

func appendCountMetrics(ctx context.Context, db *sql.DB, output *strings.Builder) error {
	output.WriteString("# HELP hostsentry_incidents_total Current incidents by status.\n# TYPE hostsentry_incidents_total gauge\n")
	rows, err := db.QueryContext(ctx, `SELECT status,count(*) FROM incidents WHERE resolved_at IS NULL GROUP BY status`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var status string
		var count int64
		if err := rows.Scan(&status, &count); err != nil {
			rows.Close()
			return err
		}
		fmt.Fprintf(output, "hostsentry_incidents_total{status=\"%s\"} %d\n", promEscape(status), count)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	output.WriteString("# HELP hostsentry_service_status Whether a monitored systemd service is active.\n# TYPE hostsentry_service_status gauge\n")
	rows, err = db.QueryContext(ctx, `SELECT host_id,service_name,active_state FROM monitored_services`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var hostID, name, state string
		if err := rows.Scan(&hostID, &name, &state); err != nil {
			rows.Close()
			return err
		}
		active := 0
		if state == "active" {
			active = 1
		}
		fmt.Fprintf(output, "hostsentry_service_status{host_id=\"%s\",service=\"%s\"} %d\n", promEscape(hostID), promEscape(name), active)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	output.WriteString("# HELP hostsentry_resource_anomaly Active statistical resource anomalies.\n# TYPE hostsentry_resource_anomaly gauge\n")
	rows, err = db.QueryContext(ctx, `SELECT host_id,fingerprint FROM incidents WHERE incident_type='resource_anomaly' AND resolved_at IS NULL`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var hostID, fingerprint string
		if err := rows.Scan(&hostID, &fingerprint); err != nil {
			rows.Close()
			return err
		}
		metric := strings.TrimPrefix(fingerprint, "anomaly:")
		fmt.Fprintf(output, "hostsentry_resource_anomaly{host_id=\"%s\",metric=\"%s\"} 1\n", promEscape(hostID), promEscape(metric))
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	output.WriteString("# HELP hostsentry_recovery_attempts_total Recovery executions by outcome.\n# TYPE hostsentry_recovery_attempts_total counter\n")
	rows, err = db.QueryContext(ctx, `SELECT outcome,count(*) FROM recovery_executions GROUP BY outcome`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var outcome string
		var count int64
		if err := rows.Scan(&outcome, &count); err != nil {
			rows.Close()
			return err
		}
		if oneOf(outcome, "succeeded", "failed", "dry_run", "approval_required") {
			fmt.Fprintf(output, "hostsentry_recovery_attempts_total{outcome=\"%s\"} %d\n", outcome, count)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	var successful, failed int64
	if err := db.QueryRowContext(ctx, `SELECT count(*) FILTER (WHERE outcome='succeeded' AND verified),count(*) FILTER (WHERE outcome='failed') FROM recovery_executions`).Scan(&successful, &failed); err != nil {
		return err
	}
	fmt.Fprintf(output, "# HELP hostsentry_recovery_success_total Verified recovery successes.\n# TYPE hostsentry_recovery_success_total counter\nhostsentry_recovery_success_total %d\n", successful)
	fmt.Fprintf(output, "# HELP hostsentry_recovery_failure_total Failed recovery executions.\n# TYPE hostsentry_recovery_failure_total counter\nhostsentry_recovery_failure_total %d\n", failed)
	return nil
}

func pagination(w http.ResponseWriter, r *http.Request) (int, int, bool) {
	limit := 50
	offset := 0
	var err error
	if value := r.URL.Query().Get("limit"); value != "" {
		limit, err = strconv.Atoi(value)
	}
	if err != nil || limit < 1 || limit > 200 {
		writeError(w, http.StatusBadRequest, "invalid_pagination", "limit must be between 1 and 200")
		return 0, 0, false
	}
	if value := r.URL.Query().Get("offset"); value != "" {
		offset, err = strconv.Atoi(value)
	}
	if err != nil || offset < 0 || offset > 100000 {
		writeError(w, http.StatusBadRequest, "invalid_pagination", "offset must be between 0 and 100000")
		return 0, 0, false
	}
	return limit, offset, true
}
func validAgentID(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '-' || char == '_' {
			continue
		}
		return false
	}
	return true
}
func oneOf(value string, options ...string) bool {
	for _, option := range options {
		if value == option {
			return true
		}
	}
	return false
}
func promEscape(value string) string {
	return strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "\n", "\\n").Replace(value)
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}
