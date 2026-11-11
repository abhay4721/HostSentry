package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hostsentry/hostsentry/internal/agent"
)

func TestProtectedSettingsRejectsMissingAndIncorrectTokens(t *testing.T) {
	api := NewAPI(nil, "a-long-metrics-token", agent.DefaultHealthWeights(), false, true, DefaultAnomalySettings())
	for _, tc := range []struct {
		name, token string
		want        int
	}{
		{name: "missing", want: http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/settings", nil)
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			res := httptest.NewRecorder()
			api.Handler().ServeHTTP(res, req)
			if res.Code != tc.want {
				t.Fatalf("status = %d, want %d", res.Code, tc.want)
			}
		})
	}
}

func TestValidUserRequiresStrongPasswordAndKnownRole(t *testing.T) {
	if !validUser("admin@example.org", "Fleet Admin", "correct horse battery staple 7", "admin") {
		t.Fatal("valid user rejected")
	}
	if validUser("not-an-email", "Fleet Admin", "correct horse battery staple 7", "admin") {
		t.Fatal("invalid email accepted")
	}
	if validUser("operator@example.org", "Operator", "short", "operator") {
		t.Fatal("weak password accepted")
	}
	if validUser("operator@example.org", "Operator", "correct horse battery staple 7", "root") {
		t.Fatal("unknown role accepted")
	}
}

func TestValidatePolicyRejectsArbitraryActionsAndMalformedUnits(t *testing.T) {
	base := policyDefinition{Name: "restart-web", ActionType: "restart_service", Service: "web.service", FailureFor: "30s", MaxAttempts: 3, Cooldown: "5m", VerificationTimeout: "30s", HostIDs: []string{"host-1"}}
	if err := validatePolicy(base); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
	base.ActionType = "run_command"
	if err := validatePolicy(base); err == nil {
		t.Fatal("arbitrary action was accepted")
	}
	base.ActionType = "restart_service"
	base.Service = "../web.service"
	if err := validatePolicy(base); err == nil {
		t.Fatal("path-like unit name was accepted")
	}
}

func TestValidateGroupRejectsDuplicateOrInvalidHostIDs(t *testing.T) {
	if err := validateGroup(hostGroup{Name: "web tier", HostIDs: []string{"host-a", "host-b"}}); err != nil {
		t.Fatalf("valid group rejected: %v", err)
	}
	if err := validateGroup(hostGroup{Name: "web tier", HostIDs: []string{"host-a", "host-a"}}); err == nil {
		t.Fatal("duplicate host assignment was accepted")
	}
	if err := validateGroup(hostGroup{Name: "web tier", HostIDs: []string{"../host"}}); err == nil {
		t.Fatal("invalid host ID was accepted")
	}
}
