package secretsengine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
)

// ---------------------------------------------------------------------------
// Shared test harness. Every *_test.go file in this package uses the helpers
// below: an httptest mock of graphql-server-go plus constructors that build
// and drive the backend through framework.Backend.HandleRequest, exactly the
// way Vault core does. `go test ./...` is hermetic — no live server, no
// network, no VAULT_ACC gate needed for any test in this file set.
// ---------------------------------------------------------------------------

// mockGraphQL emulates the exact operation surface documented in
// graphql_operations.go: login / me / createUser / deleteUser /
// createServiceAccount / deleteServiceAccount, speaking
// {"query": "<document>"} with no variables and bearer auth in the
// Authorization header. Default admin credentials mirror graphql-server-go's
// seeded admin/changeme.
type mockGraphQL struct {
	t   *testing.T
	srv *httptest.Server

	mu              sync.Mutex
	sessionSeq      int
	accountSeq      int
	validSessions   map[string]bool
	users           map[string]string // username -> id
	serviceAccounts map[string]string // name -> id

	// Behavior knobs for failure-path tests. Always mutate via the setters so
	// access is synchronized with the server goroutine.
	strictDelete        bool   // deletes of absent accounts return a GraphQL error instead of idempotent true
	echoSessionAsSecret bool   // createServiceAccount echoes the caller's bearer back as the new secret
	failAll             string // when non-empty, every operation fails with this GraphQL error message
}

func newMockGraphQL(t *testing.T) *mockGraphQL {
	m := &mockGraphQL{
		t:               t,
		validSessions:   map[string]bool{},
		users:           map[string]string{},
		serviceAccounts: map[string]string{},
	}
	m.srv = httptest.NewServer(http.HandlerFunc(m.handle))
	t.Cleanup(m.srv.Close)
	return m
}

// graphqlURL is the value to put in the backend config's "url" field. The
// /graphql path is appended explicitly so the tests don't depend on the
// client's bare-host defaulting behavior.
func (m *mockGraphQL) graphqlURL() string { return m.srv.URL + "/graphql" }

func (m *mockGraphQL) setStrictDelete(v bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.strictDelete = v
}

func (m *mockGraphQL) setEchoSessionAsSecret(v bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.echoSessionAsSecret = v
}

func (m *mockGraphQL) setFailAll(msg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failAll = msg
}

// addSession registers a token as a valid session without going through
// login, simulating a token persisted in config storage by a previous run.
func (m *mockGraphQL) addSession(tok string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.validSessions[tok] = true
}

func (m *mockGraphQL) addUser(username, id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[username] = id
}

func (m *mockGraphQL) hasUser(username string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.users[username]
	return ok
}

func (m *mockGraphQL) hasSA(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.serviceAccounts[name]
	return ok
}

func (m *mockGraphQL) removeSA(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.serviceAccounts, name)
}

func (m *mockGraphQL) saCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.serviceAccounts)
}

func (m *mockGraphQL) loginCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessionSeq
}

func (m *mockGraphQL) handle(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var body struct {
		Query string `json:"query"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "malformed request body", http.StatusBadRequest)
		return
	}
	q := body.Query
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

	m.mu.Lock()
	defer m.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	data := func(v interface{}) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": v})
	}
	gqlErr := func(msg string) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data":   nil,
			"errors": []map[string]interface{}{{"message": msg}},
		})
	}
	authed := func() bool { return m.validSessions[bearer] }

	if m.failAll != "" {
		gqlErr(m.failAll)
		return
	}

	switch {
	case strings.Contains(q, "login("):
		// Open mutation; bare username/password args per the schema.
		if extractArg(q, "username") != "admin" || extractArg(q, "password") != "changeme" {
			gqlErr("invalid credentials")
			return
		}
		m.sessionSeq++
		tok := fmt.Sprintf("session-%d", m.sessionSeq)
		m.validSessions[tok] = true
		data(map[string]interface{}{"login": map[string]interface{}{
			"token": tok,
			"user":  map[string]interface{}{"id": "usr_admin"},
		}})

	case strings.Contains(q, "createServiceAccount("):
		if !authed() {
			gqlErr("unauthorized")
			return
		}
		name := extractArg(q, "name")
		m.accountSeq++
		id := fmt.Sprintf("sa_%d", m.accountSeq)
		secret := fmt.Sprintf("sa-secret-%d", m.accountSeq)
		if m.echoSessionAsSecret {
			// Misbehaving server: hands the caller's own bearer back as the
			// "new" credential. The client must reject this.
			secret = bearer
		}
		m.serviceAccounts[name] = id
		data(map[string]interface{}{"createServiceAccount": map[string]interface{}{
			"serviceAccount": map[string]interface{}{"id": id, "name": name},
			"secret":         secret,
		}})

	case strings.Contains(q, "deleteServiceAccount("):
		if !authed() {
			gqlErr("unauthorized")
			return
		}
		name := extractArg(q, "name")
		if _, ok := m.serviceAccounts[name]; !ok && m.strictDelete {
			gqlErr("service account not found")
			return
		}
		delete(m.serviceAccounts, name)
		data(map[string]interface{}{"deleteServiceAccount": true})

	case strings.Contains(q, "createUser("):
		// Open on the real server; no auth check here either.
		username := extractArg(q, "username")
		m.accountSeq++
		id := fmt.Sprintf("usr_%d", m.accountSeq)
		m.users[username] = id
		data(map[string]interface{}{"createUser": map[string]interface{}{
			"id": id, "username": username,
		}})

	case strings.Contains(q, "deleteUser("):
		if !authed() {
			gqlErr("unauthorized")
			return
		}
		username := extractArg(q, "username")
		if _, ok := m.users[username]; !ok && m.strictDelete {
			gqlErr("user not found")
			return
		}
		delete(m.users, username)
		data(map[string]interface{}{"deleteUser": true})

	case strings.HasPrefix(strings.TrimSpace(q), "query"):
		// opMe is the only query the plugin sends; both union members alias
		// to the same payload shape client-side, so returning the User arm
		// suffices.
		if !authed() {
			gqlErr("unauthorized")
			return
		}
		data(map[string]interface{}{"me": map[string]interface{}{
			"id": "usr_admin", "username": "admin",
		}})

	default:
		gqlErr("unhandled operation in mock: " + q)
	}
}

// extractArg pulls the value of `arg: "<value>"` out of a query document.
// Test fixtures never contain escaped quotes, so a naive scan is enough.
func extractArg(query, arg string) string {
	marker := arg + `: "`
	i := strings.Index(query, marker)
	if i < 0 {
		return ""
	}
	rest := query[i+len(marker):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return ""
	}
	return rest[:j]
}

// ---------------------------------------------------------------------------
// Backend constructors / request helpers
// ---------------------------------------------------------------------------

func getTestBackend(t *testing.T) (*graphqlBackend, logical.Storage) {
	t.Helper()
	config := logical.TestBackendConfig()
	config.StorageView = new(logical.InmemStorage)
	config.Logger = hclog.NewNullLogger() // keep test output quiet
	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatalf("building backend: %v", err)
	}
	return b.(*graphqlBackend), config.StorageView
}

// configureBackend writes config/ pointing the backend at the mock server.
func configureBackend(t *testing.T, b *graphqlBackend, s logical.Storage, mock *mockGraphQL) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      configStoragePath,
		Storage:   s,
		Data: map[string]interface{}{
			"username": "admin",
			"password": "changeme",
			"url":      mock.graphqlURL(),
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("writing config: resp=%#v err=%v", resp, err)
	}
}

// writeRole writes role/<name>; per pathRolesWrite the response carries a
// freshly minted leased credential.
func writeRole(t *testing.T, b *graphqlBackend, s logical.Storage, name, username string, ttl, maxTTL int) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/" + name,
		Storage:   s,
		Data: map[string]interface{}{
			"username": username,
			"ttl":      ttl,
			"max_ttl":  maxTTL,
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("writing role %q: resp=%#v err=%v", name, resp, err)
	}
	return resp
}

// readCreds reads creds/<role>, minting a new leased credential.
func readCreds(t *testing.T, b *graphqlBackend, s logical.Storage, role string) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/" + role,
		Storage:   s,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("reading creds/%s: resp=%#v err=%v", role, resp, err)
	}
	return resp
}

// ---------------------------------------------------------------------------
// backend.go tests
// ---------------------------------------------------------------------------

func TestFactory(t *testing.T) {
	b, _ := getTestBackend(t)
	// The secret type must be registered or no lease lifecycle exists.
	if b.Secret(graphqlTokenType) == nil {
		t.Fatalf("secret type %q not registered on backend", graphqlTokenType)
	}
}

func TestGetClientUnconfigured(t *testing.T) {
	b, s := getTestBackend(t)
	if _, err := b.getClient(context.Background(), s); err == nil ||
		!strings.Contains(err.Error(), "not configured") {
		t.Fatalf("expected not-configured error, got %v", err)
	}
}

func TestGetClientCachedAndInvalidated(t *testing.T) {
	ctx := context.Background()
	mock := newMockGraphQL(t)
	b, s := getTestBackend(t)
	configureBackend(t, b, s, mock)

	c1, err := b.getClient(ctx, s)
	if err != nil {
		t.Fatalf("getClient: %v", err)
	}
	c2, err := b.getClient(ctx, s)
	if err != nil {
		t.Fatalf("getClient (cached): %v", err)
	}
	if c1 != c2 {
		t.Fatalf("expected cached client to be reused; got distinct instances")
	}

	// Unrelated storage keys must not drop the cache.
	b.invalidate(ctx, "role/whatever")
	b.lock.RLock()
	cached := b.client
	b.lock.RUnlock()
	if cached == nil {
		t.Fatalf("client cache dropped on unrelated storage invalidation")
	}

	// A config change must.
	b.invalidate(ctx, configStoragePath)
	b.lock.RLock()
	cached = b.client
	b.lock.RUnlock()
	if cached != nil {
		t.Fatalf("client cache survived config invalidation")
	}
}

func TestGetSessionPersistsTokenAndReuses(t *testing.T) {
	ctx := context.Background()
	mock := newMockGraphQL(t)
	b, s := getTestBackend(t)
	configureBackend(t, b, s, mock)

	_, tok, err := b.getSession(ctx, s)
	if err != nil {
		t.Fatalf("getSession: %v", err)
	}
	if tok == "" {
		t.Fatalf("getSession returned empty session token")
	}

	// The refreshed token must be written back to config storage.
	cfg, err := getConfig(ctx, s)
	if err != nil {
		t.Fatalf("getConfig: %v", err)
	}
	if cfg.Token != tok {
		t.Fatalf("session token not persisted to config: stored %q, want %q", cfg.Token, tok)
	}

	// A second getSession must reuse the session, not log in again.
	_, tok2, err := b.getSession(ctx, s)
	if err != nil {
		t.Fatalf("getSession (second): %v", err)
	}
	if tok2 != tok {
		t.Fatalf("session token changed across calls: %q -> %q", tok, tok2)
	}
	if mock.loginCount() != 1 {
		t.Fatalf("expected exactly 1 upstream login, got %d", mock.loginCount())
	}
}

func TestGetSessionSurvivesClientRebuild(t *testing.T) {
	ctx := context.Background()
	mock := newMockGraphQL(t)
	b, s := getTestBackend(t)
	configureBackend(t, b, s, mock)

	_, tok, err := b.getSession(ctx, s)
	if err != nil {
		t.Fatalf("getSession: %v", err)
	}

	// Simulate plugin restart / cache invalidation: the rebuilt client is
	// seeded from config.Token, so no new login happens.
	b.reset()
	_, tok2, err := b.getSession(ctx, s)
	if err != nil {
		t.Fatalf("getSession after reset: %v", err)
	}
	if tok2 != tok {
		t.Fatalf("rebuilt client minted a new session: %q -> %q", tok, tok2)
	}
	if mock.loginCount() != 1 {
		t.Fatalf("expected stored session reuse after rebuild; logins=%d", mock.loginCount())
	}
}
