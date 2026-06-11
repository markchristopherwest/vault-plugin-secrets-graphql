package secretsengine

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func readConfig(t *testing.T, b *graphqlBackend, s logical.Storage) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      configStoragePath,
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("reading config: %v", err)
	}
	return resp
}

func TestConfigCreateAndRead(t *testing.T) {
	mock := newMockGraphQL(t)
	b, s := getTestBackend(t)
	configureBackend(t, b, s, mock)

	resp := readConfig(t, b, s)
	if resp == nil || resp.IsError() {
		t.Fatalf("config read failed: %#v", resp)
	}
	if got := resp.Data["username"]; got != "admin" {
		t.Errorf("username = %v, want admin", got)
	}
	if got := resp.Data["url"]; got != mock.graphqlURL() {
		t.Errorf("url = %v, want %v", got, mock.graphqlURL())
	}
	if got := resp.Data["has_session_token"]; got != false {
		t.Errorf("has_session_token = %v before any session, want false", got)
	}
	// Sensitive fields must never be returned.
	for _, key := range []string{"password", "token"} {
		if _, ok := resp.Data[key]; ok {
			t.Errorf("sensitive field %q leaked on config read", key)
		}
	}
}

func TestConfigCreateMissingFields(t *testing.T) {
	b, s := getTestBackend(t)
	// url and password absent → create must fail.
	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      configStoragePath,
		Storage:   s,
		Data:      map[string]interface{}{"username": "admin"},
	})
	if err == nil {
		t.Fatalf("expected error creating config without url/password")
	}
}

func TestConfigUpdatePreservesUnsetFields(t *testing.T) {
	mock := newMockGraphQL(t)
	b, s := getTestBackend(t)
	configureBackend(t, b, s, mock)

	// Update only the password; username and url must survive.
	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configStoragePath,
		Storage:   s,
		Data:      map[string]interface{}{"password": "rotated"},
	}); err != nil {
		t.Fatalf("updating config: %v", err)
	}

	resp := readConfig(t, b, s)
	if got := resp.Data["username"]; got != "admin" {
		t.Errorf("username lost on partial update: %v", got)
	}
	if got := resp.Data["url"]; got != mock.graphqlURL() {
		t.Errorf("url lost on partial update: %v", got)
	}
}

// TestConfigWriteClearsStoredSession: any credential/URL change invalidates
// the stored session token so the next request logs in fresh instead of
// presenting a token minted against the old configuration.
func TestConfigWriteClearsStoredSession(t *testing.T) {
	ctx := context.Background()
	mock := newMockGraphQL(t)
	b, s := getTestBackend(t)
	configureBackend(t, b, s, mock)

	// Establish and persist a session.
	if _, _, err := b.getSession(ctx, s); err != nil {
		t.Fatalf("getSession: %v", err)
	}
	if got := readConfig(t, b, s).Data["has_session_token"]; got != true {
		t.Fatalf("session token not persisted; has_session_token = %v", got)
	}

	// Rewrite config: stored token must be cleared.
	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configStoragePath,
		Storage:   s,
		Data:      map[string]interface{}{"password": "changeme"},
	}); err != nil {
		t.Fatalf("updating config: %v", err)
	}
	if got := readConfig(t, b, s).Data["has_session_token"]; got != false {
		t.Errorf("stored session token survived a config write; has_session_token = %v", got)
	}

	// And the cached client must have been reset.
	b.lock.RLock()
	cached := b.client
	b.lock.RUnlock()
	if cached != nil {
		t.Errorf("cached client survived a config write")
	}
}

// TestConfigUpdateWithoutConfig exercises the explicit-update guard in
// pathConfigWrite directly: HandleRequest would reroute the operation via the
// existence check, so the callback is invoked straight.
func TestConfigUpdateWithoutConfig(t *testing.T) {
	b, s := getTestBackend(t)
	d := &framework.FieldData{
		Raw:    map[string]interface{}{"username": "admin"},
		Schema: pathConfig(b).Fields,
	}
	_, err := b.pathConfigWrite(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configStoragePath,
		Storage:   s,
	}, d)
	if err == nil || !strings.Contains(err.Error(), "config not found") {
		t.Fatalf("expected config-not-found error on update without config, got %v", err)
	}
}

func TestConfigDelete(t *testing.T) {
	ctx := context.Background()
	mock := newMockGraphQL(t)
	b, s := getTestBackend(t)
	configureBackend(t, b, s, mock)

	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      configStoragePath,
		Storage:   s,
	}); err != nil {
		t.Fatalf("deleting config: %v", err)
	}
	if resp := readConfig(t, b, s); resp != nil {
		t.Fatalf("config read after delete returned %#v, want nil", resp)
	}
	// And clients are no longer constructible.
	if _, err := b.getClient(ctx, s); err == nil {
		t.Fatalf("getClient succeeded after config delete")
	}
}
