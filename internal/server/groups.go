package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
)

var groupIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var groupNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.-]{0,79}$`)

type hostGroup struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	HostIDs   []string `json:"host_ids"`
	HostCount int      `json:"host_count"`
}

func (a *API) listGroups(w http.ResponseWriter, r *http.Request) {
	rows, err := a.db.QueryContext(r.Context(), `SELECT g.id::text,g.name,COALESCE(array_agg(m.host_id) FILTER(WHERE m.host_id IS NOT NULL),ARRAY[]::text[])
		FROM host_groups g LEFT JOIN host_group_members m ON m.group_id=g.id GROUP BY g.id ORDER BY g.name`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query_failed", "host groups could not be loaded")
		return
	}
	defer rows.Close()
	items := make([]hostGroup, 0)
	for rows.Next() {
		var item hostGroup
		if err := rows.Scan(&item.ID, &item.Name, &item.HostIDs); err != nil {
			writeError(w, http.StatusInternalServerError, "query_failed", "host groups could not be loaded")
			return
		}
		item.HostCount = len(item.HostIDs)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "query_failed", "host groups could not be loaded")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (a *API) createGroup(w http.ResponseWriter, r *http.Request) {
	var item hostGroup
	if err := decodeGroup(w, r, &item); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_group", err.Error())
		return
	}
	item.Name = strings.TrimSpace(item.Name)
	if err := validateGroup(item); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_group", err.Error())
		return
	}
	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "storage_failed", "group could not be created")
		return
	}
	defer tx.Rollback()
	if err := tx.QueryRowContext(r.Context(), `INSERT INTO host_groups(name) VALUES ($1) RETURNING id::text`, item.Name).Scan(&item.ID); err != nil {
		writeError(w, http.StatusConflict, "group_conflict", "group name already exists")
		return
	}
	if err := replaceGroupHosts(r.Context(), tx, item.ID, item.HostIDs); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_hosts", "one or more hosts do not exist")
		return
	}
	if _, err := tx.ExecContext(r.Context(), `INSERT INTO audit_logs(actor,action,target) VALUES ($1,'host_group_created',$2)`, currentUser(r).Email, item.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "storage_failed", "group audit could not be recorded")
		return
	}
	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "storage_failed", "group could not be created")
		return
	}
	item.HostCount = len(item.HostIDs)
	writeJSON(w, http.StatusCreated, item)
}

func (a *API) updateGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !groupIDPattern.MatchString(id) {
		writeError(w, http.StatusBadRequest, "invalid_group_id", "group id is invalid")
		return
	}
	var item hostGroup
	if err := decodeGroup(w, r, &item); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_group", err.Error())
		return
	}
	item.Name = strings.TrimSpace(item.Name)
	if err := validateGroup(item); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_group", err.Error())
		return
	}
	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "storage_failed", "group could not be updated")
		return
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(r.Context(), `UPDATE host_groups SET name=$2 WHERE id=$1`, id, item.Name)
	if err != nil {
		writeError(w, http.StatusConflict, "group_conflict", "group name already exists")
		return
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		writeError(w, http.StatusNotFound, "group_not_found", "group does not exist")
		return
	}
	if err := replaceGroupHosts(r.Context(), tx, id, item.HostIDs); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_hosts", "one or more hosts do not exist")
		return
	}
	if _, err := tx.ExecContext(r.Context(), `INSERT INTO audit_logs(actor,action,target) VALUES ($1,'host_group_updated',$2)`, currentUser(r).Email, id); err != nil {
		writeError(w, http.StatusInternalServerError, "storage_failed", "group audit could not be recorded")
		return
	}
	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "storage_failed", "group could not be updated")
		return
	}
	item.ID = id
	item.HostCount = len(item.HostIDs)
	writeJSON(w, http.StatusOK, item)
}

func (a *API) deleteGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !groupIDPattern.MatchString(id) {
		writeError(w, http.StatusBadRequest, "invalid_group_id", "group id is invalid")
		return
	}
	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "delete_failed", "group could not be deleted")
		return
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(r.Context(), `DELETE FROM host_groups WHERE id=$1`, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "delete_failed", "group could not be deleted")
		return
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		writeError(w, http.StatusNotFound, "group_not_found", "group does not exist")
		return
	}
	if _, err := tx.ExecContext(r.Context(), `INSERT INTO audit_logs(actor,action,target) VALUES ($1,'host_group_deleted',$2)`, currentUser(r).Email, id); err != nil {
		writeError(w, http.StatusInternalServerError, "delete_failed", "group audit could not be recorded")
		return
	}
	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "delete_failed", "group could not be deleted")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func decodeGroup(w http.ResponseWriter, r *http.Request, item *hostGroup) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(item); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("request must contain one JSON object")
	}
	return nil
}

func validateGroup(item hostGroup) error {
	item.Name = strings.TrimSpace(item.Name)
	if !groupNamePattern.MatchString(item.Name) {
		return errors.New("group name must be 1 to 80 safe characters")
	}
	seen := make(map[string]struct{}, len(item.HostIDs))
	for _, hostID := range item.HostIDs {
		if !validAgentID(hostID) {
			return errors.New("host id is invalid")
		}
		if _, ok := seen[hostID]; ok {
			return errors.New("host ids must be unique")
		}
		seen[hostID] = struct{}{}
	}
	return nil
}

func replaceGroupHosts(ctx context.Context, tx *sql.Tx, id string, hostIDs []string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM host_group_members WHERE group_id=$1`, id); err != nil {
		return err
	}
	for _, hostID := range hostIDs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO host_group_members(host_id,group_id) VALUES ($1,$2)`, hostID, id); err != nil {
			return err
		}
	}
	return nil
}
