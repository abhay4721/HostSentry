package server

import "testing"

func clearNotifierEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{"HOSTSENTRY_NOTIFY_SEVERITIES", "HOSTSENTRY_NOTIFY_TYPES", "HOSTSENTRY_TELEGRAM_BOT_TOKEN", "HOSTSENTRY_TELEGRAM_CHAT_ID", "HOSTSENTRY_GITHUB_TOKEN", "HOSTSENTRY_GITHUB_REPOSITORY", "HOSTSENTRY_GITHUB_LABELS", "HOSTSENTRY_SMTP_ADDRESS", "HOSTSENTRY_SMTP_USERNAME", "HOSTSENTRY_SMTP_PASSWORD", "HOSTSENTRY_SMTP_FROM", "HOSTSENTRY_SMTP_TO"} {
		t.Setenv(key, "")
	}
}

func TestNotifierRequiresGitHubTokenAndRepositoryTogether(t *testing.T) {
	clearNotifierEnv(t)
	t.Setenv("HOSTSENTRY_GITHUB_TOKEN", "test-token")
	if _, err := NewNotifierFromEnv(); err == nil {
		t.Fatal("partial GitHub notification configuration was accepted")
	}
	clearNotifierEnv(t)
	t.Setenv("HOSTSENTRY_GITHUB_TOKEN", "test-token")
	t.Setenv("HOSTSENTRY_GITHUB_REPOSITORY", "owner/repo")
	notifier, err := NewNotifierFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if len(notifier.EnabledChannels()) != 1 || notifier.EnabledChannels()[0] != "github" {
		t.Fatalf("GitHub channel missing: %v", notifier.EnabledChannels())
	}
}

func TestNotifierDefaultsToNoExternalChannelsAndCriticalSeverities(t *testing.T) {
	clearNotifierEnv(t)
	notifier, err := NewNotifierFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if got := len(notifier.EnabledChannels()); got != 0 {
		t.Fatalf("channels = %d, want none", got)
	}
	if !notifier.severities["critical"] || !notifier.severities["warning"] || notifier.severities["info"] {
		t.Fatalf("unexpected default severity filter: %#v", notifier.severities)
	}
}

func TestNotifierRequiresTelegramCredentialsTogether(t *testing.T) {
	clearNotifierEnv(t)
	t.Setenv("HOSTSENTRY_TELEGRAM_BOT_TOKEN", "test-token")
	if _, err := NewNotifierFromEnv(); err == nil {
		t.Fatal("partial Telegram configuration was accepted")
	}
}

func TestNotifierRejectsUnknownSeverityAndIncidentFilters(t *testing.T) {
	clearNotifierEnv(t)
	t.Setenv("HOSTSENTRY_NOTIFY_SEVERITIES", "urgent")
	if _, err := NewNotifierFromEnv(); err == nil {
		t.Fatal("unknown severity filter was accepted")
	}
	clearNotifierEnv(t)
	t.Setenv("HOSTSENTRY_NOTIFY_TYPES", "shell_command")
	if _, err := NewNotifierFromEnv(); err == nil {
		t.Fatal("unknown incident type filter was accepted")
	}
}

func TestNotifierRequiresEncryptedSMTPSetupFields(t *testing.T) {
	clearNotifierEnv(t)
	t.Setenv("HOSTSENTRY_SMTP_ADDRESS", "mail.example.org:587")
	if _, err := NewNotifierFromEnv(); err == nil {
		t.Fatal("SMTP without sender and recipient was accepted")
	}
	t.Setenv("HOSTSENTRY_SMTP_FROM", "alerts@example.org")
	t.Setenv("HOSTSENTRY_SMTP_TO", "ops@example.org")
	if _, err := NewNotifierFromEnv(); err != nil {
		t.Fatalf("valid STARTTLS configuration rejected: %v", err)
	}
}
