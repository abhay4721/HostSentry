package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/mail"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID          string    `json:"id"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
	Role        string    `json:"role"`
	Disabled    bool      `json:"disabled"`
	CreatedAt   time.Time `json:"created_at"`
}

type userContextKey struct{}
type loginAttempt struct {
	Started time.Time
	Count   int
}

var loginAttempts = struct {
	sync.Mutex
	values map[string]loginAttempt
}{values: make(map[string]loginAttempt)}
var errInvalidSession = errors.New("invalid session")

const passwordHashCost = 12

var dummyPasswordHash, _ = bcrypt.GenerateFromPassword([]byte("hostsentry-invalid-user-padding-secret"), passwordHashCost)

func BootstrapAdmin(ctx context.Context, db *sql.DB, email, password string) error {
	var count int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM users").Scan(&count); err != nil {
		return fmt.Errorf("check bootstrap admin: %w", err)
	}
	if count > 0 {
		return nil
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if _, err := mail.ParseAddress(email); err != nil || len(email) > 254 {
		return errors.New("HOSTSENTRY_BOOTSTRAP_ADMIN_EMAIL must be a valid email address")
	}
	if len(password) < 14 || len(password) > 72 {
		return errors.New("HOSTSENTRY_BOOTSTRAP_ADMIN_PASSWORD must be 14 to 72 bytes")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), passwordHashCost)
	if err != nil {
		return fmt.Errorf("hash bootstrap password: %w", err)
	}
	name := strings.SplitN(email, "@", 2)[0]
	if _, err := db.ExecContext(ctx, `INSERT INTO users(email,display_name,password_hash,role) VALUES($1,$2,$3,'admin') ON CONFLICT(email) DO NOTHING`, email, name, string(hash)); err != nil {
		return fmt.Errorf("create bootstrap admin: %w", err)
	}
	return nil
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	if !allowLogin(remoteAddress(r)) {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many login attempts; try again later")
		return
	}
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_login", "email and password are required")
		return
	}
	body.Email = strings.ToLower(strings.TrimSpace(body.Email))
	var user User
	var hash string
	err := a.db.QueryRowContext(r.Context(), `SELECT id::text,email,display_name,role,disabled,created_at,password_hash FROM users WHERE email=$1`, body.Email).Scan(&user.ID, &user.Email, &user.DisplayName, &user.Role, &user.Disabled, &user.CreatedAt, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		_ = bcrypt.CompareHashAndPassword(dummyPasswordHash, []byte(body.Password))
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "email or password is incorrect")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "login_failed", "login could not be completed")
		return
	}
	if user.Disabled || bcrypt.CompareHashAndPassword([]byte(hash), []byte(body.Password)) != nil {
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "email or password is incorrect")
		return
	}
	clearLoginAttempts(remoteAddress(r))
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		writeError(w, http.StatusInternalServerError, "session_failed", "session could not be created")
		return
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	digest := sha256.Sum256([]byte(token))
	if _, err := a.db.ExecContext(r.Context(), `DELETE FROM user_sessions WHERE expires_at<=now()`); err != nil {
		writeError(w, http.StatusInternalServerError, "session_failed", "session could not be created")
		return
	}
	if _, err := a.db.ExecContext(r.Context(), `INSERT INTO user_sessions(token_hash,user_id,expires_at) VALUES($1,$2,now()+interval '12 hours')`, hex.EncodeToString(digest[:]), user.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "session_failed", "session could not be created")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "expires_in": 43200, "user": user})
}

func allowLogin(key string) bool {
	loginAttempts.Lock()
	defer loginAttempts.Unlock()
	now := time.Now()
	attempt := loginAttempts.values[key]
	if now.Sub(attempt.Started) >= 15*time.Minute {
		attempt = loginAttempt{Started: now}
	}
	if len(loginAttempts.values) > 10000 {
		for k, v := range loginAttempts.values {
			if now.Sub(v.Started) >= 15*time.Minute {
				delete(loginAttempts.values, k)
			}
		}
	}
	if attempt.Count >= 10 {
		return false
	}
	attempt.Count++
	loginAttempts.values[key] = attempt
	return true
}

func clearLoginAttempts(key string) {
	loginAttempts.Lock()
	delete(loginAttempts.values, key)
	loginAttempts.Unlock()
}

func remoteAddress(r *http.Request) string {
	if forwarded := strings.TrimSpace(r.Header.Get("X-Real-IP")); forwarded != "" {
		return forwarded
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
func bearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
}

func (a *API) authenticate(ctx context.Context, token string) (User, error) {
	if len(token) < 32 || len(token) > 256 {
		return User{}, errors.New("invalid token")
	}
	digest := sha256.Sum256([]byte(token))
	var user User
	err := a.db.QueryRowContext(ctx, `SELECT u.id::text,u.email,u.display_name,u.role,u.disabled,u.created_at FROM user_sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now()`, hex.EncodeToString(digest[:])).Scan(&user.ID, &user.Email, &user.DisplayName, &user.Role, &user.Disabled, &user.CreatedAt)
	if err != nil {
		return User{}, err
	}
	if user.Disabled {
		return User{}, errInvalidSession
	}
	return user, nil
}

func currentUser(r *http.Request) User { u, _ := r.Context().Value(userContextKey{}).(User); return u }
func (a *API) currentUser(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, currentUser(r))
}
func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	digest := sha256.Sum256([]byte(token))
	if _, err := a.db.ExecContext(r.Context(), `DELETE FROM user_sessions WHERE token_hash=$1`, hex.EncodeToString(digest[:])); err != nil {
		writeError(w, http.StatusInternalServerError, "logout_failed", "session could not be ended")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) listUsers(w http.ResponseWriter, r *http.Request) {
	rows, err := a.db.QueryContext(r.Context(), `SELECT id::text,email,display_name,role,disabled,created_at FROM users ORDER BY email`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query_failed", "users could not be loaded")
		return
	}
	defer rows.Close()
	items := make([]User, 0)
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Email, &u.DisplayName, &u.Role, &u.Disabled, &u.CreatedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "query_failed", "users could not be loaded")
			return
		}
		items = append(items, u)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "query_failed", "users could not be loaded")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (a *API) createUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email       string `json:"email"`
		DisplayName string `json:"display_name"`
		Password    string `json:"password"`
		Role        string `json:"role"`
	}
	if err := decodeStrictJSON(w, r, bodyLimitUser, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_user", "request body is invalid")
		return
	}
	body.Email = strings.ToLower(strings.TrimSpace(body.Email))
	body.DisplayName = strings.TrimSpace(body.DisplayName)
	if !validUser(body.Email, body.DisplayName, body.Password, body.Role) {
		writeError(w, http.StatusBadRequest, "invalid_user", "email, display name, password, or role is invalid")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), passwordHashCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "user_failed", "user could not be created")
		return
	}
	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "user_failed", "user could not be created")
		return
	}
	defer tx.Rollback()
	var user User
	err = tx.QueryRowContext(r.Context(), `INSERT INTO users(email,display_name,password_hash,role) VALUES($1,$2,$3,$4) RETURNING id::text,email,display_name,role,disabled,created_at`, body.Email, body.DisplayName, string(hash), body.Role).Scan(&user.ID, &user.Email, &user.DisplayName, &user.Role, &user.Disabled, &user.CreatedAt)
	if err != nil {
		writeError(w, http.StatusConflict, "user_conflict", "a user with this email already exists")
		return
	}
	if _, err := tx.ExecContext(r.Context(), `INSERT INTO audit_logs(actor,action,target) VALUES($1,'user_created',$2)`, currentUser(r).Email, user.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "user_failed", "user audit could not be recorded")
		return
	}
	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "user_failed", "user could not be created")
		return
	}
	writeJSON(w, http.StatusCreated, user)
}

func (a *API) updateUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !policyIDPattern.MatchString(id) {
		writeError(w, http.StatusBadRequest, "invalid_user_id", "user id is invalid")
		return
	}
	var body struct {
		Role     *string `json:"role"`
		Disabled *bool   `json:"disabled"`
		Password string  `json:"password"`
	}
	if err := decodeStrictJSON(w, r, bodyLimitUser, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_user", "request body is invalid")
		return
	}
	if body.Role == nil && body.Disabled == nil && body.Password == "" {
		writeError(w, http.StatusBadRequest, "invalid_user", "at least one user change is required")
		return
	}
	if body.Role != nil && *body.Role != "admin" && *body.Role != "operator" && *body.Role != "viewer" {
		writeError(w, http.StatusBadRequest, "invalid_user", "role must be admin, operator, or viewer")
		return
	}
	if body.Password != "" && (len(body.Password) < 14 || len(body.Password) > 72) {
		writeError(w, http.StatusBadRequest, "invalid_user", "password must be 14 to 72 bytes")
		return
	}
	passwordHash := ""
	if body.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), passwordHashCost)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "user_failed", "user could not be updated")
			return
		}
		passwordHash = string(hash)
	}
	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "user_failed", "user could not be updated")
		return
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(r.Context(), `SELECT pg_advisory_xact_lock(1280492114)`); err != nil {
		writeError(w, http.StatusInternalServerError, "user_failed", "user could not be updated")
		return
	}
	var userRole string
	var disabled bool
	if err := tx.QueryRowContext(r.Context(), `SELECT role,disabled FROM users WHERE id=$1 FOR UPDATE`, id).Scan(&userRole, &disabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "user_not_found", "user does not exist")
		} else {
			writeError(w, http.StatusInternalServerError, "query_failed", "user could not be loaded")
		}
		return
	}
	newRole := userRole
	if body.Role != nil {
		newRole = *body.Role
	}
	newDisabled := disabled
	if body.Disabled != nil {
		newDisabled = *body.Disabled
	}
	if userRole == "admin" && (newRole != "admin" || newDisabled) {
		var admins int
		if err := tx.QueryRowContext(r.Context(), `SELECT count(*) FROM users WHERE role='admin' AND disabled=false AND id<>$1`, id).Scan(&admins); err != nil || admins == 0 {
			writeError(w, http.StatusConflict, "last_admin", "at least one enabled admin must remain")
			return
		}
	}
	var user User
	err = tx.QueryRowContext(r.Context(), `UPDATE users SET role=$2,disabled=$3,password_hash=CASE WHEN $4='' THEN password_hash ELSE $4 END,updated_at=now() WHERE id=$1 RETURNING id::text,email,display_name,role,disabled,created_at`, id, newRole, newDisabled, passwordHash).Scan(&user.ID, &user.Email, &user.DisplayName, &user.Role, &user.Disabled, &user.CreatedAt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "user_failed", "user could not be updated")
		return
	}
	if user.Disabled || body.Password != "" {
		if _, err := tx.ExecContext(r.Context(), `DELETE FROM user_sessions WHERE user_id=$1`, id); err != nil {
			writeError(w, http.StatusInternalServerError, "user_failed", "user sessions could not be revoked")
			return
		}
	}
	if _, err := tx.ExecContext(r.Context(), `INSERT INTO audit_logs(actor,action,target) VALUES($1,'user_updated',$2)`, currentUser(r).Email, user.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "user_failed", "user audit could not be recorded")
		return
	}
	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "user_failed", "user could not be updated")
		return
	}
	writeJSON(w, http.StatusOK, user)
}

const bodyLimitUser = 16 << 10

func validUser(email, name, password, role string) bool {
	if _, err := mail.ParseAddress(email); err != nil || len(email) > 254 || strings.ContainsAny(email, " <>\"'") {
		return false
	}
	if strings.TrimSpace(name) == "" || len(name) > 120 || len(password) < 14 || len(password) > 72 {
		return false
	}
	return role == "admin" || role == "operator" || role == "viewer"
}
func decodeStrictJSON(w http.ResponseWriter, r *http.Request, limit int64, target any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request must contain one JSON object")
	}
	return nil
}
