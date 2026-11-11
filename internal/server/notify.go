package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

type IncidentNotification struct {
	HostID      string
	Type        string
	Severity    string
	Description string
	DetectedAt  time.Time
}

type Notifier struct {
	severities    map[string]bool
	types         map[string]bool
	telegramToken string
	telegramChat  string
	githubToken   string
	githubRepo    string
	githubLabels  []string
	smtpAddress   string
	smtpUsername  string
	smtpPassword  string
	smtpFrom      string
	smtpTo        []string
	client        *http.Client
}

func NewNotifierFromEnv() (*Notifier, error) {
	severitySetting := os.Getenv("HOSTSENTRY_NOTIFY_SEVERITIES")
	if strings.TrimSpace(severitySetting) == "" {
		severitySetting = "critical,warning"
	}
	n := &Notifier{severities: parseSet(severitySetting), types: parseSet(os.Getenv("HOSTSENTRY_NOTIFY_TYPES")), telegramToken: strings.TrimSpace(os.Getenv("HOSTSENTRY_TELEGRAM_BOT_TOKEN")), telegramChat: strings.TrimSpace(os.Getenv("HOSTSENTRY_TELEGRAM_CHAT_ID")), githubToken: strings.TrimSpace(os.Getenv("HOSTSENTRY_GITHUB_TOKEN")), githubRepo: strings.TrimSpace(os.Getenv("HOSTSENTRY_GITHUB_REPOSITORY")), githubLabels: parseList(os.Getenv("HOSTSENTRY_GITHUB_LABELS")), smtpAddress: strings.TrimSpace(os.Getenv("HOSTSENTRY_SMTP_ADDRESS")), smtpUsername: os.Getenv("HOSTSENTRY_SMTP_USERNAME"), smtpPassword: os.Getenv("HOSTSENTRY_SMTP_PASSWORD"), smtpFrom: strings.TrimSpace(os.Getenv("HOSTSENTRY_SMTP_FROM")), client: &http.Client{Timeout: 8 * time.Second}}
	for _, severity := range strings.Split(os.Getenv("HOSTSENTRY_NOTIFY_SEVERITIES"), ",") {
		severity = strings.ToLower(strings.TrimSpace(severity))
		if severity != "" && severity != "critical" && severity != "warning" && severity != "error" && severity != "info" {
			return nil, fmt.Errorf("unsupported notification severity %q", severity)
		}
	}
	for incidentType := range n.types {
		if incidentType != "resource_threshold" && incidentType != "systemd_service_failed" && incidentType != "resource_anomaly" {
			return nil, fmt.Errorf("unsupported notification type %q", incidentType)
		}
	}
	if (n.telegramToken == "") != (n.telegramChat == "") {
		return nil, errors.New("HOSTSENTRY_TELEGRAM_BOT_TOKEN and HOSTSENTRY_TELEGRAM_CHAT_ID must be configured together")
	}
	if (n.githubToken == "") != (n.githubRepo == "") {
		return nil, errors.New("HOSTSENTRY_GITHUB_TOKEN and HOSTSENTRY_GITHUB_REPOSITORY must be configured together")
	}
	if n.githubRepo != "" {
		parts := strings.Split(n.githubRepo, "/")
		if len(parts) != 2 || !githubPathPart.MatchString(parts[0]) || !githubPathPart.MatchString(parts[1]) {
			return nil, errors.New("HOSTSENTRY_GITHUB_REPOSITORY must be owner/repository")
		}
	}
	if n.smtpAddress != "" {
		if _, _, err := net.SplitHostPort(n.smtpAddress); err != nil {
			return nil, errors.New("HOSTSENTRY_SMTP_ADDRESS must be host:port")
		}
		if n.smtpFrom == "" || strings.TrimSpace(os.Getenv("HOSTSENTRY_SMTP_TO")) == "" {
			return nil, errors.New("SMTP address requires HOSTSENTRY_SMTP_FROM and HOSTSENTRY_SMTP_TO")
		}
		for _, address := range strings.Split(os.Getenv("HOSTSENTRY_SMTP_TO"), ",") {
			address = strings.TrimSpace(address)
			if address == "" {
				continue
			}
			parsed, err := mail.ParseAddress(address)
			if err != nil {
				return nil, errors.New("HOSTSENTRY_SMTP_TO contains an invalid address")
			}
			n.smtpTo = append(n.smtpTo, parsed.Address)
		}
		if len(n.smtpTo) == 0 {
			return nil, errors.New("HOSTSENTRY_SMTP_TO has no recipients")
		}
		if (n.smtpUsername == "") != (n.smtpPassword == "") {
			return nil, errors.New("SMTP username and password must be configured together")
		}
	}
	if n.smtpAddress != "" {
		parsed, err := mail.ParseAddress(n.smtpFrom)
		if err != nil {
			return nil, errors.New("HOSTSENTRY_SMTP_FROM is invalid")
		}
		n.smtpFrom = parsed.Address
	}
	return n, nil
}

func parseSet(raw string) map[string]bool {
	out := map[string]bool{}
	for _, part := range strings.Split(strings.ToLower(raw), ",") {
		value := strings.TrimSpace(part)
		if value != "" {
			out[value] = true
		}
	}
	return out
}

func parseList(raw string) []string {
	items := make([]string, 0)
	for _, part := range strings.Split(raw, ",") {
		value := strings.TrimSpace(part)
		if value != "" {
			items = append(items, value)
		}
	}
	return items
}

func (n *Notifier) EnabledChannels() []string {
	if n == nil {
		return []string{}
	}
	channels := make([]string, 0, 3)
	if n.telegramToken != "" {
		channels = append(channels, "telegram")
	}
	if n.githubToken != "" {
		channels = append(channels, "github")
	}
	if n.smtpAddress != "" {
		channels = append(channels, "smtp")
	}
	return channels
}

func (n *Notifier) Notify(ctx context.Context, event IncidentNotification) {
	if n == nil {
		return
	}
	if len(n.severities) > 0 && !n.severities[strings.ToLower(event.Severity)] {
		return
	}
	if len(n.types) > 0 && !n.types[strings.ToLower(event.Type)] {
		return
	}
	if n.telegramToken != "" {
		if err := n.sendTelegram(ctx, event); err != nil {
			slog.Warn("incident Telegram notification failed", "host", event.HostID, "type", event.Type, "error", err)
		}
	}
	if n.githubToken != "" {
		if err := n.sendGitHub(ctx, event); err != nil {
			slog.Warn("incident GitHub notification failed", "host", event.HostID, "type", event.Type, "error", err)
		}
	}
	if n.smtpAddress != "" {
		if err := n.sendSMTP(ctx, event); err != nil {
			slog.Warn("incident SMTP notification failed", "host", event.HostID, "type", event.Type, "error", err)
		}
	}
}

var githubPathPart = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)

func (n *Notifier) sendGitHub(ctx context.Context, event IncidentNotification) error {
	parts := strings.Split(n.githubRepo, "/")
	payload := map[string]any{"title": fmt.Sprintf("[HostSentry] %s incident on %s", event.Severity, event.HostID), "body": formatNotification(event), "labels": n.githubLabels}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	endpoint := "https://api.github.com/repos/" + url.PathEscape(parts[0]) + "/" + url.PathEscape(parts[1]) + "/issues"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+n.githubToken)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("GitHub API returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func (n *Notifier) sendTelegram(ctx context.Context, event IncidentNotification) error {
	form := url.Values{"chat_id": {n.telegramChat}, "text": {formatNotification(event)}, "disable_web_page_preview": {"true"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.telegram.org/bot"+url.PathEscape(n.telegramToken)+"/sendMessage", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Telegram API returned HTTP %d", resp.StatusCode)
	}
	var result struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(body, &result); err != nil || !result.OK {
		return errors.New("Telegram API rejected the notification")
	}
	return nil
}

func (n *Notifier) sendSMTP(ctx context.Context, event IncidentNotification) error {
	message := []byte("From: " + n.smtpFrom + "\r\nTo: " + strings.Join(n.smtpTo, ", ") + "\r\nSubject: [HostSentry] " + event.Severity + " incident on " + event.HostID + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + formatNotification(event) + "\r\n")
	host, port, err := net.SplitHostPort(n.smtpAddress)
	if err != nil {
		return err
	}
	var conn net.Conn
	dialer := net.Dialer{Timeout: 5 * time.Second}
	if port == "465" {
		conn, err = tls.DialWithDialer(&dialer, "tcp", n.smtpAddress, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host})
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", n.smtpAddress)
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer client.Close()
	if port != "465" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return errors.New("SMTP server does not offer STARTTLS")
		}
		if err := client.StartTLS(&tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}); err != nil {
			return err
		}
	}
	if n.smtpUsername != "" {
		if ok, _ := client.Extension("AUTH"); !ok {
			return errors.New("SMTP server does not offer authentication")
		}
		var auth smtp.Auth = smtp.PlainAuth("", n.smtpUsername, n.smtpPassword, host)
		if port == "465" {
			auth = implicitTLSPlainAuth{username: n.smtpUsername, password: n.smtpPassword, host: host}
		}
		if err := client.Auth(auth); err != nil {
			return err
		}
	}
	if err := client.Mail(n.smtpFrom); err != nil {
		return err
	}
	for _, recipient := range n.smtpTo {
		if err := client.Rcpt(recipient); err != nil {
			return err
		}
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := writer.Write(message); err != nil {
		_ = writer.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return client.Quit()
}

type implicitTLSPlainAuth struct{ username, password, host string }

func (a implicitTLSPlainAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if server.Name != a.host {
		return "", nil, errors.New("SMTP server name mismatch")
	}
	return "PLAIN", []byte("\x00" + a.username + "\x00" + a.password), nil
}

func (implicitTLSPlainAuth) Next([]byte, bool) ([]byte, error) {
	return nil, errors.New("unexpected SMTP authentication challenge")
}

func formatNotification(event IncidentNotification) string {
	return fmt.Sprintf("Host: %s\nSeverity: %s\nIncident: %s\nDetected: %s\n%s", event.HostID, event.Severity, event.Type, event.DetectedAt.UTC().Format(time.RFC3339), event.Description)
}
