package secretsengine

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hashicorp/go-hclog"
)

// newTestClient builds a client straight from config (no backend), the same
// way backend.getClient does, with a null logger standing in for
// b.Logger().Named("client").
func newTestClient(t *testing.T, cfg *graphqlConfig) *graphqlClient {
	t.Helper()
	c, err := newClient(cfg)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	c.logger = hclog.NewNullLogger()
	return c
}

func testClientConfig(mock *mockGraphQL) *graphqlConfig {
	return &graphqlConfig{
		Username: "admin",
		Password: "changeme",
		URL:      mock.graphqlURL(),
	}
}

func TestEnsureSessionFreshLogin(t *testing.T) {
	ctx := context.Background()
	mock := newMockGraphQL(t)
	c := newTestClient(t, testClientConfig(mock))

	tok, refreshed, err := c.ensureSession(ctx)
	if err != nil {
		t.Fatalf("ensureSession: %v", err)
	}
	if !refreshed {
		t.Fatalf("first session with no stored token must report refreshed=true")
	}
	if tok == "" {
		t.Fatalf("ensureSession returned empty token")
	}

	// Second call: same session, no refresh, no extra login.
	tok2, refreshed2, err := c.ensureSession(ctx)
	if err != nil {
		t.Fatalf("ensureSession (second): %v", err)
	}
	if refreshed2 {
		t.Fatalf("valid session re-reported as refreshed")
	}
	if tok2 != tok {
		t.Fatalf("session token changed without refresh: %q -> %q", tok, tok2)
	}
	if mock.loginCount() != 1 {
		t.Fatalf("expected 1 login, got %d", mock.loginCount())
	}
}

func TestEnsureSessionReusesSeededToken(t *testing.T) {
	ctx := context.Background()
	mock := newMockGraphQL(t)
	// Token persisted by a previous run, still valid upstream: the client
	// must vet it (opMe) and reuse it without logging in.
	mock.addSession("preseeded-token")

	cfg := testClientConfig(mock)
	cfg.Token = "preseeded-token"
	c := newTestClient(t, cfg)

	tok, refreshed, err := c.ensureSession(ctx)
	if err != nil {
		t.Fatalf("ensureSession: %v", err)
	}
	if refreshed {
		t.Fatalf("valid stored token must not be refreshed")
	}
	if tok != "preseeded-token" {
		t.Fatalf("expected stored token to be reused, got %q", tok)
	}
	if mock.loginCount() != 0 {
		t.Fatalf("expected no upstream login, got %d", mock.loginCount())
	}
}

func TestEnsureSessionReplacesStaleToken(t *testing.T) {
	ctx := context.Background()
	mock := newMockGraphQL(t)

	// Token persisted by a previous run but no longer valid upstream
	// (server restarted, JWT expired, etc.): vetting fails, client logs in.
	cfg := testClientConfig(mock)
	cfg.Token = "stale-token"
	c := newTestClient(t, cfg)

	tok, refreshed, err := c.ensureSession(ctx)
	if err != nil {
		t.Fatalf("ensureSession: %v", err)
	}
	if !refreshed {
		t.Fatalf("stale token must trigger a refresh")
	}
	if tok == "" || tok == "stale-token" {
		t.Fatalf("expected a freshly minted token, got %q", tok)
	}
	if mock.loginCount() != 1 {
		t.Fatalf("expected exactly 1 login replacing the stale token, got %d", mock.loginCount())
	}
}

func TestEnsureSessionBadCredentials(t *testing.T) {
	ctx := context.Background()
	mock := newMockGraphQL(t)

	cfg := testClientConfig(mock)
	cfg.Password = "wrong"
	c := newTestClient(t, cfg)

	if _, _, err := c.ensureSession(ctx); err == nil ||
		!strings.Contains(err.Error(), "invalid credentials") {
		t.Fatalf("expected upstream credential error to surface, got %v", err)
	}
}

func TestCreateServiceAccount(t *testing.T) {
	ctx := context.Background()
	mock := newMockGraphQL(t)
	c := newTestClient(t, testClientConfig(mock))

	session, _, err := c.ensureSession(ctx)
	if err != nil {
		t.Fatalf("ensureSession: %v", err)
	}

	const name = "vault-admin-deadbeef"
	auth, err := c.CreateServiceAccount(ctx, session, name)
	if err != nil {
		t.Fatalf("CreateServiceAccount: %v", err)
	}
	if auth.Username != name {
		t.Errorf("Username = %q, want %q", auth.Username, name)
	}
	if !strings.HasPrefix(auth.UserID, "sa_") {
		t.Errorf("UserID = %q, want sa_-prefixed id", auth.UserID)
	}
	if auth.Token == "" {
		t.Errorf("Token is empty")
	}
	if auth.Token == session {
		t.Errorf("returned credential equals the session bearer; must be the new account's token")
	}
	if !mock.hasSA(name) {
		t.Errorf("service account %q not provisioned upstream", name)
	}
}

func TestCreateServiceAccountRejectsSessionEcho(t *testing.T) {
	ctx := context.Background()
	mock := newMockGraphQL(t)
	c := newTestClient(t, testClientConfig(mock))

	session, _, err := c.ensureSession(ctx)
	if err != nil {
		t.Fatalf("ensureSession: %v", err)
	}

	// A server that hands the admin session back as the "new" secret would
	// leak root-equivalent access into every lease; the client hard-fails.
	mock.setEchoSessionAsSecret(true)
	if _, err := c.CreateServiceAccount(ctx, session, "vault-admin-echo"); err == nil {
		t.Fatalf("expected error when server echoes the session token as the credential")
	}
}

func TestDeleteServiceAccountIdempotent(t *testing.T) {
	ctx := context.Background()
	mock := newMockGraphQL(t)
	c := newTestClient(t, testClientConfig(mock))

	session, _, err := c.ensureSession(ctx)
	if err != nil {
		t.Fatalf("ensureSession: %v", err)
	}

	// Deleting an absent account is idempotent upstream — no error.
	if err := c.DeleteServiceAccount(ctx, session, "never-existed"); err != nil {
		t.Fatalf("idempotent delete of absent service account errored: %v", err)
	}

	// Create-then-delete actually removes it.
	const name = "vault-admin-cafef00d"
	if _, err := c.CreateServiceAccount(ctx, session, name); err != nil {
		t.Fatalf("CreateServiceAccount: %v", err)
	}
	if err := c.DeleteServiceAccount(ctx, session, name); err != nil {
		t.Fatalf("DeleteServiceAccount: %v", err)
	}
	if mock.hasSA(name) {
		t.Fatalf("service account %q still present after delete", name)
	}
}

func TestDeleteUser(t *testing.T) {
	ctx := context.Background()
	mock := newMockGraphQL(t)
	mock.addUser("legacy-user", "usr_legacy")
	c := newTestClient(t, testClientConfig(mock))

	session, _, err := c.ensureSession(ctx)
	if err != nil {
		t.Fatalf("ensureSession: %v", err)
	}
	if err := c.DeleteUser(ctx, session, "legacy-user"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if mock.hasUser("legacy-user") {
		t.Fatalf("user still present after delete")
	}
}

func TestGraphQLErrorSurfaced(t *testing.T) {
	ctx := context.Background()
	mock := newMockGraphQL(t)
	mock.setFailAll("synthetic upstream failure")
	c := newTestClient(t, testClientConfig(mock))

	if _, _, err := c.ensureSession(ctx); err == nil ||
		!strings.Contains(err.Error(), "synthetic upstream failure") {
		t.Fatalf("expected upstream GraphQL error message in error chain, got %v", err)
	}
}

func TestIsCredentialGone(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"unauthorized", errors.New("graphql: unauthorized"), true},
		{"not found", errors.New("graphql: service account not found"), true},
		{"network error", errors.New("dial tcp 127.0.0.1:1: connect: connection refused"), false},
		{"unrelated server error", errors.New("internal server error: disk full"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isCredentialGone(tc.err); got != tc.want {
				t.Errorf("isCredentialGone(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
