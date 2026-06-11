package secretsengine

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestRoleWriteRequiresUsername(t *testing.T) {
	b, s := getTestBackend(t)
	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test",
		Storage:   s,
		Data:      map[string]interface{}{"ttl": 300},
	})
	if err == nil || !strings.Contains(err.Error(), "missing username") {
		t.Fatalf("expected missing-username error, got %v", err)
	}
}

func TestRoleTTLValidation(t *testing.T) {
	b, s := getTestBackend(t)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test",
		Storage:   s,
		Data: map[string]interface{}{
			"username": "admin",
			"ttl":      600,
			"max_ttl":  300,
		},
	})
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected ErrorResponse for ttl > max_ttl, got %#v", resp)
	}
	if msg := resp.Error().Error(); !strings.Contains(msg, "ttl cannot be greater") {
		t.Errorf("error = %q, want ttl validation message", msg)
	}
}

// TestRoleWriteIssuesLeasedCredential: writing a role both persists the
// definition and returns a working, lease_id-bearing credential — the same
// issuance path creds/<role> reads use.
func TestRoleWriteIssuesLeasedCredential(t *testing.T) {
	mock := newMockGraphQL(t)
	b, s := getTestBackend(t)
	configureBackend(t, b, s, mock)

	resp := writeRole(t, b, s, "test", "admin", 300, 3600)
	if resp == nil || resp.Secret == nil {
		t.Fatalf("role write returned no leased secret: %#v", resp)
	}
	if tok, _ := resp.Data["token"].(string); tok == "" {
		t.Errorf("role write returned empty token")
	}
	saName, _ := resp.Data["username"].(string)
	if !strings.HasPrefix(saName, "vault-admin-") {
		t.Errorf("service account name = %q, want vault-admin-<id> form", saName)
	}
	if !mock.hasSA(saName) {
		t.Errorf("role write did not provision %q upstream", saName)
	}
}

// TestRoleReadReturnsDefinition: reading role/<name> returns the role config,
// not a credential — issuance lives at creds/<name>.
func TestRoleReadReturnsDefinition(t *testing.T) {
	mock := newMockGraphQL(t)
	b, s := getTestBackend(t)
	configureBackend(t, b, s, mock)
	writeRole(t, b, s, "test", "admin", 300, 3600)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/test",
		Storage:   s,
	})
	if err != nil || resp == nil {
		t.Fatalf("reading role: resp=%#v err=%v", resp, err)
	}
	if resp.Secret != nil {
		t.Errorf("role read returned a lease; issuance belongs to creds/")
	}
	if got := resp.Data["username"]; got != "admin" {
		t.Errorf("username = %v, want admin", got)
	}
	if got := resp.Data["ttl"]; got != float64(300) {
		t.Errorf("ttl = %v (%T), want 300 seconds", got, got)
	}
	if got := resp.Data["max_ttl"]; got != float64(3600) {
		t.Errorf("max_ttl = %v (%T), want 3600 seconds", got, got)
	}
}

func TestRoleUpdatePreservesUsername(t *testing.T) {
	mock := newMockGraphQL(t)
	b, s := getTestBackend(t)
	configureBackend(t, b, s, mock)
	writeRole(t, b, s, "test", "admin", 300, 3600)

	// Update only the TTL; username must survive. (The update also mints a
	// fresh credential — that's the documented write behavior.)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/test",
		Storage:   s,
		Data:      map[string]interface{}{"ttl": 120},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("updating role: resp=%#v err=%v", resp, err)
	}

	role, err := b.getRole(context.Background(), s, "test")
	if err != nil || role == nil {
		t.Fatalf("getRole after update: role=%#v err=%v", role, err)
	}
	if role.Username != "admin" {
		t.Errorf("username lost on partial update: %q", role.Username)
	}
	if role.TTL.Seconds() != 120 {
		t.Errorf("ttl = %s, want 2m0s", role.TTL)
	}
}

// TestRoleWriteUnconfiguredPersistsRole: with no backend config, issuance
// fails — but the role definition is persisted first, so the operator can
// read creds/<role> once config is written, without re-writing the role.
func TestRoleWriteUnconfiguredPersistsRole(t *testing.T) {
	b, s := getTestBackend(t)
	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test",
		Storage:   s,
		Data:      map[string]interface{}{"username": "admin", "ttl": 300, "max_ttl": 3600},
	})
	if err == nil || !strings.Contains(err.Error(), "credential issuance failed") {
		t.Fatalf("expected issuance failure on unconfigured backend, got %v", err)
	}

	role, gerr := b.getRole(context.Background(), s, "test")
	if gerr != nil {
		t.Fatalf("getRole: %v", gerr)
	}
	if role == nil {
		t.Fatalf("role not persisted despite documented saved-but-issuance-failed semantics")
	}
}

func TestRoleListAndDelete(t *testing.T) {
	ctx := context.Background()
	mock := newMockGraphQL(t)
	b, s := getTestBackend(t)
	configureBackend(t, b, s, mock)
	writeRole(t, b, s, "alpha", "admin", 300, 3600)
	writeRole(t, b, s, "beta", "admin", 300, 3600)

	listResp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation,
		Path:      "role/",
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("listing roles: %v", err)
	}
	keys, _ := listResp.Data["keys"].([]string)
	if len(keys) != 2 {
		t.Fatalf("role list = %v, want [alpha beta]", keys)
	}

	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "role/alpha",
		Storage:   s,
	}); err != nil {
		t.Fatalf("deleting role: %v", err)
	}
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/alpha",
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("reading deleted role: %v", err)
	}
	if resp != nil {
		t.Fatalf("deleted role still readable: %#v", resp)
	}
}
