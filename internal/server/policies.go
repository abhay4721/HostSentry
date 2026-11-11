package server

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/hostsentry/hostsentry/internal/agent"
)

var policyIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

type policyDefinition struct {
	ID                  string   `json:"id,omitempty"`
	Name                string   `json:"name"`
	ActionType          string   `json:"action_type"`
	Service             string   `json:"service"`
	FailureFor          string   `json:"failure_for"`
	MaxAttempts         int      `json:"max_attempts"`
	Cooldown            string   `json:"cooldown"`
	VerificationTimeout string   `json:"verification_timeout"`
	RequireApproval     bool     `json:"require_approval"`
	Enabled             bool     `json:"enabled"`
	HostIDs             []string `json:"host_ids"`
}

func (a *API) listPolicies(w http.ResponseWriter, r *http.Request) {
	rows, err := a.db.QueryContext(r.Context(), `SELECT p.id::text,p.name,p.action_type,p.service,p.failure_for,p.max_attempts,p.cooldown,p.verification_timeout,p.require_approval,p.enabled,
		COALESCE(array_agg(ph.host_id) FILTER (WHERE ph.host_id IS NOT NULL),ARRAY[]::text[])
		FROM recovery_policies p LEFT JOIN recovery_policy_hosts ph ON ph.policy_id=p.id
		GROUP BY p.id ORDER BY p.name`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query_failed", "recovery policies could not be loaded")
		return
	}
	defer rows.Close()
	items := make([]policyDefinition, 0)
	for rows.Next() {
		var item policyDefinition
		if err := rows.Scan(&item.ID, &item.Name, &item.ActionType, &item.Service, &item.FailureFor, &item.MaxAttempts, &item.Cooldown, &item.VerificationTimeout, &item.RequireApproval, &item.Enabled, &item.HostIDs); err != nil {
			writeError(w, http.StatusInternalServerError, "query_failed", "recovery policies could not be loaded")
			return
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "query_failed", "recovery policies could not be loaded")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "recovery_enabled": a.recoveryEnabled, "dry_run": a.recoveryDryRun})
}

func (a *API) createPolicy(w http.ResponseWriter, r *http.Request) {
	var item policyDefinition
	if err := decodePolicy(w, r, &item); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_policy", err.Error())
		return
	}
	if err := validatePolicy(item); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_policy", err.Error())
		return
	}
	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "storage_failed", "policy could not be saved")
		return
	}
	defer tx.Rollback()
	var id string
	err = tx.QueryRowContext(r.Context(), `INSERT INTO recovery_policies
		(name,action_type,service,failure_for,max_attempts,cooldown,verification_timeout,require_approval,enabled)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id::text`, item.Name, item.ActionType, item.Service, item.FailureFor, item.MaxAttempts, item.Cooldown, item.VerificationTimeout, item.RequireApproval, item.Enabled).Scan(&id)
	if err != nil {
		writeError(w, http.StatusConflict, "policy_conflict", "policy name already exists or host assignment is invalid")
		return
	}
	if err := replacePolicyHosts(r.Context(), tx, id, item.HostIDs); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_hosts", "one or more assigned hosts do not exist")
		return
	}
	if err := bumpPolicyVersion(r.Context(), tx, currentUser(r).Email, "policy_created", id); err != nil {
		writeError(w, http.StatusInternalServerError, "storage_failed", "policy could not be saved")
		return
	}
	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "storage_failed", "policy could not be saved")
		return
	}
	item.ID = id
	writeJSON(w, http.StatusCreated, item)
}

func (a *API) updatePolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !policyIDPattern.MatchString(id) {
		writeError(w, http.StatusBadRequest, "invalid_policy_id", "policy id is invalid")
		return
	}
	var item policyDefinition
	if err := decodePolicy(w, r, &item); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_policy", err.Error())
		return
	}
	if err := validatePolicy(item); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_policy", err.Error())
		return
	}
	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "storage_failed", "policy could not be updated")
		return
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(r.Context(), `UPDATE recovery_policies SET name=$2,action_type=$3,service=$4,failure_for=$5,max_attempts=$6,cooldown=$7,verification_timeout=$8,require_approval=$9,enabled=$10,updated_at=now() WHERE id=$1`, id, item.Name, item.ActionType, item.Service, item.FailureFor, item.MaxAttempts, item.Cooldown, item.VerificationTimeout, item.RequireApproval, item.Enabled)
	if err != nil {
		writeError(w, http.StatusConflict, "policy_conflict", "policy update conflicts with an existing policy")
		return
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		writeError(w, http.StatusNotFound, "policy_not_found", "policy does not exist")
		return
	}
	if err := replacePolicyHosts(r.Context(), tx, id, item.HostIDs); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_hosts", "one or more assigned hosts do not exist")
		return
	}
	if err := bumpPolicyVersion(r.Context(), tx, currentUser(r).Email, "policy_updated", id); err != nil {
		writeError(w, http.StatusInternalServerError, "storage_failed", "policy could not be updated")
		return
	}
	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "storage_failed", "policy could not be updated")
		return
	}
	item.ID = id
	writeJSON(w, http.StatusOK, item)
}

func (a *API) disablePolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !policyIDPattern.MatchString(id) {
		writeError(w, http.StatusBadRequest, "invalid_policy_id", "policy id is invalid")
		return
	}
	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "storage_failed", "policy could not be disabled")
		return
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(r.Context(), `UPDATE recovery_policies SET enabled=false,updated_at=now() WHERE id=$1`, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "storage_failed", "policy could not be disabled")
		return
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		writeError(w, http.StatusNotFound, "policy_not_found", "policy does not exist")
		return
	}
	if err := bumpPolicyVersion(r.Context(), tx, currentUser(r).Email, "policy_disabled", id); err != nil {
		writeError(w, http.StatusInternalServerError, "storage_failed", "policy could not be disabled")
		return
	}
	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "storage_failed", "policy could not be disabled")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) agentPolicies(w http.ResponseWriter, r *http.Request) {
	hostID, ok := a.agentIdentity(w, r)
	if !ok {
		return
	}
	var version int64
	if err := a.db.QueryRowContext(r.Context(), `SELECT version FROM policy_version WHERE singleton=true`).Scan(&version); err != nil {
		writeError(w, http.StatusServiceUnavailable, "policy_unavailable", "policy version could not be loaded")
		return
	}
	rows, err := a.db.QueryContext(r.Context(), `SELECT p.name,p.enabled,p.service,p.failure_for,p.max_attempts,p.cooldown,p.verification_timeout,p.require_approval
		FROM recovery_policies p JOIN recovery_policy_hosts ph ON ph.policy_id=p.id WHERE ph.host_id=$1 ORDER BY p.name`, hostID)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "policy_unavailable", "policies could not be loaded")
		return
	}
	defer rows.Close()
	policies := make([]agent.RecoveryPolicy, 0)
	for rows.Next() {
		var policy agent.RecoveryPolicy
		var failureFor, cooldown, verify string
		if err := rows.Scan(&policy.Name, &policy.Enabled, &policy.Service, &failureFor, &policy.MaxAttempts, &cooldown, &verify, &policy.RequireApproval); err != nil {
			writeError(w, http.StatusServiceUnavailable, "policy_unavailable", "policies could not be loaded")
			return
		}
		failureDuration, err := time.ParseDuration(failureFor)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "policy_unavailable", "policy duration is invalid")
			return
		}
		cooldownDuration, err := time.ParseDuration(cooldown)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "policy_unavailable", "policy duration is invalid")
			return
		}
		verifyDuration, err := time.ParseDuration(verify)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "policy_unavailable", "policy duration is invalid")
			return
		}
		policy.FailureFor = agent.Duration(failureDuration)
		policy.Cooldown = agent.Duration(cooldownDuration)
		policy.VerificationTimeout = agent.Duration(verifyDuration)
		policies = append(policies, policy)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusServiceUnavailable, "policy_unavailable", "policies could not be loaded")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": version, "enabled": a.recoveryEnabled, "dry_run": a.recoveryDryRun, "policies": policies})
}

func (a *API) agentIdentity(w http.ResponseWriter, r *http.Request) (string, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		writeError(w, http.StatusUnauthorized, "agent_certificate_required", "a verified agent client certificate is required")
		return "", false
	}
	identity := r.TLS.PeerCertificates[0].Subject.CommonName
	if !validAgentID(identity) || r.Header.Get("X-HostSentry-Agent") != identity {
		writeError(w, http.StatusUnauthorized, "agent_identity_mismatch", "certificate identity does not match agent id")
		return "", false
	}
	fingerprint := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
	var revoked bool
	if err := a.db.QueryRowContext(r.Context(), `SELECT EXISTS(SELECT 1 FROM revoked_certificates WHERE fingerprint=$1)`, hex.EncodeToString(fingerprint[:])).Scan(&revoked); err != nil {
		writeError(w, http.StatusServiceUnavailable, "certificate_check_failed", "agent certificate status could not be checked")
		return "", false
	}
	if revoked {
		writeError(w, http.StatusUnauthorized, "agent_certificate_revoked", "agent certificate has been revoked")
		return "", false
	}
	return identity, true
}

func (a *API) revokeCertificate(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		HostID      string `json:"host_id"`
		Fingerprint string `json:"fingerprint"`
		Reason      string `json:"reason"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "certificate revocation request is invalid")
		return
	}
	payload.Fingerprint = strings.ToLower(strings.ReplaceAll(payload.Fingerprint, ":", ""))
	if !validAgentID(payload.HostID) || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(payload.Fingerprint) || len(payload.Reason) > 512 {
		writeError(w, http.StatusBadRequest, "invalid_revocation", "host id, SHA-256 fingerprint, or reason is invalid")
		return
	}
	actor := currentUser(r).Email
	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "revocation_failed", "certificate could not be revoked")
		return
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(r.Context(), `INSERT INTO revoked_certificates(fingerprint,host_id,reason,actor) VALUES ($1,$2,$3,$4) ON CONFLICT(fingerprint) DO UPDATE SET reason=EXCLUDED.reason,actor=EXCLUDED.actor`, payload.Fingerprint, payload.HostID, payload.Reason, actor); err != nil {
		writeError(w, http.StatusInternalServerError, "revocation_failed", "certificate could not be revoked")
		return
	}
	if _, err := tx.ExecContext(r.Context(), `INSERT INTO audit_logs(actor,action,target,details) VALUES ($1,'certificate_revoked',$2,jsonb_build_object('reason',$3::text))`, actor, payload.HostID, payload.Reason); err != nil {
		writeError(w, http.StatusInternalServerError, "revocation_failed", "certificate revocation audit could not be recorded")
		return
	}
	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "revocation_failed", "certificate could not be revoked")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func decodePolicy(w http.ResponseWriter, r *http.Request, item *policyDefinition) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(item); err != nil {
		return errors.New("request body is invalid")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("request must contain one JSON object")
	}
	return nil
}

func validatePolicy(item policyDefinition) error {
	if !validPolicyName(item.Name) {
		return errors.New("name must use letters, digits, hyphen, or underscore")
	}
	if item.ActionType != "restart_service" {
		return errors.New("action_type must be restart_service")
	}
	if !validUnitName(item.Service) {
		return errors.New("service must be a valid .service unit name")
	}
	if item.MaxAttempts < 1 || item.MaxAttempts > 10 {
		return errors.New("max_attempts must be between 1 and 10")
	}
	for name, spec := range map[string]struct {
		value            string
		minimum, maximum time.Duration
	}{
		"failure_for":          {item.FailureFor, 0, 24 * time.Hour},
		"cooldown":             {item.Cooldown, time.Second, 24 * time.Hour},
		"verification_timeout": {item.VerificationTimeout, time.Second, 5 * time.Minute},
	} {
		value, err := time.ParseDuration(spec.value)
		if err != nil || value < spec.minimum || value > spec.maximum {
			return fmt.Errorf("%s is outside the supported duration range", name)
		}
	}
	seen := make(map[string]struct{}, len(item.HostIDs))
	if len(item.HostIDs) == 0 {
		return errors.New("at least one host assignment is required")
	}
	for _, hostID := range item.HostIDs {
		if !validAgentID(hostID) {
			return errors.New("host id is invalid")
		}
		if _, ok := seen[hostID]; ok {
			return errors.New("host assignments must be unique")
		}
		seen[hostID] = struct{}{}
	}
	return nil
}

func validPolicyName(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_' {
			continue
		}
		return false
	}
	return true
}

func validUnitName(value string) bool {
	if !strings.HasSuffix(value, ".service") || len(value) < len("x.service") {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || strings.ContainsRune("_.:@-", char) {
			continue
		}
		return false
	}
	return true
}

func replacePolicyHosts(ctx context.Context, tx *sql.Tx, policyID string, hosts []string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_policy_hosts WHERE policy_id=$1`, policyID); err != nil {
		return err
	}
	for _, hostID := range hosts {
		if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_policy_hosts(policy_id,host_id) VALUES ($1,$2)`, policyID, hostID); err != nil {
			return err
		}
	}
	return nil
}

func bumpPolicyVersion(ctx context.Context, tx *sql.Tx, actor, action, target string) error {
	if _, err := tx.ExecContext(ctx, `UPDATE policy_version SET version=version+1 WHERE singleton=true`); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO audit_logs(actor,action,target) VALUES ($1,$2,$3)`, actor, action, target)
	return err
}
