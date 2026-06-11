package secretsengine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

// revoke drives the registered Revoke callback through HandleRequest the way
// Vault's expiration manager does, using the secret returned at issue time
// (its InternalData already carries secret_type from framework.Secret.Response).
func revoke(t *testing.T, b *graphqlBackend, s logical.Storage, secret *logical.Secret) error {
	t.Helper()
	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RevokeOperation,
		Storage:   s,
		Secret:    secret,
	})
	return err
}

func TestTokenRevokeServiceAccount(t *testing.T) {
	ctx := context.Background()
	mock := newMockGraphQL(t)
	b, s := getTestBackend(t)
	configureBackend(t, b, s, mock)
	writeRole(t, b, s, "test", "admin", 300, 3600)

	resp := readCreds(t, b, s, "test")
	saName := resp.Data["username"].(string)
	tokenID := resp.Data["token_id"].(string)
	if !mock.hasSA(saName) {
		t.Fatalf("service account %q not provisioned at issue time", saName)
	}

	if err := revoke(t, b, s, resp.Secret); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// Upstream account destroyed...
	if mock.hasSA(saName) {
		t.Errorf("service account %q still exists upstream after revoke", saName)
	}
	// ...and the token/<token_id> record removed.
	entry, err := s.Get(ctx, tokenStoragePrefix+tokenID)
	if err != nil {
		t.Fatalf("storage get: %v", err)
	}
	if entry != nil {
		t.Errorf("credential record token/%s survived revoke", tokenID)
	}
}

// TestTokenRevokeAlreadyGoneUpstream exercises the isCredentialGone
// hardening end-to-end: when the upstream account was deleted out-of-band and
// the server errors on delete, revoke must still succeed so Vault's
// revocation queue can't wedge on an impossible operation.
func TestTokenRevokeAlreadyGoneUpstream(t *testing.T) {
	ctx := context.Background()
	mock := newMockGraphQL(t)
	b, s := getTestBackend(t)
	configureBackend(t, b, s, mock)
	writeRole(t, b, s, "test", "admin", 300, 3600)

	resp := readCreds(t, b, s, "test")
	saName := resp.Data["username"].(string)
	tokenID := resp.Data["token_id"].(string)

	// Simulate out-of-band deletion plus a server that errors (rather than
	// returning idempotent true) on deletes of absent accounts.
	mock.removeSA(saName)
	mock.setStrictDelete(true)

	if err := revoke(t, b, s, resp.Secret); err != nil {
		t.Fatalf("revoke of already-gone credential must succeed, got %v", err)
	}
	entry, err := s.Get(ctx, tokenStoragePrefix+tokenID)
	if err != nil {
		t.Fatalf("storage get: %v", err)
	}
	if entry != nil {
		t.Errorf("credential record token/%s survived revoke", tokenID)
	}
}

// TestTokenRevokeLegacyUserLease covers leases minted by older builds whose
// InternalData carries account_type "user" (or nothing): revocation must
// route through deleteUser, not deleteServiceAccount.
func TestTokenRevokeLegacyUserLease(t *testing.T) {
	for _, accountType := range []string{accountTypeUser, ""} {
		t.Run("account_type="+accountType, func(t *testing.T) {
			mock := newMockGraphQL(t)
			b, s := getTestBackend(t)
			configureBackend(t, b, s, mock)
			mock.addUser("vault-legacy-1234abcd", "usr_legacy")

			internal := map[string]interface{}{
				"secret_type": graphqlTokenType, // routes RevokeOperation to this secret's callbacks
				"token_id":    "legacy-token-id",
				"username":    "vault-legacy-1234abcd",
				"user_id":     "usr_legacy",
				"role":        "test",
			}
			if accountType != "" {
				internal["account_type"] = accountType
			}

			if err := revoke(t, b, s, &logical.Secret{InternalData: internal}); err != nil {
				t.Fatalf("revoke: %v", err)
			}
			if mock.hasUser("vault-legacy-1234abcd") {
				t.Errorf("legacy dynamic user still exists upstream after revoke")
			}
		})
	}
}

// TestTokenRevokeMissingNameFails: a lease with only an id can't be revoked
// upstream (the server deletes by name); the backend must fail loudly so the
// operator cleans up instead of silently leaking the account.
func TestTokenRevokeMissingNameFails(t *testing.T) {
	mock := newMockGraphQL(t)
	b, s := getTestBackend(t)
	configureBackend(t, b, s, mock)

	err := revoke(t, b, s, &logical.Secret{InternalData: map[string]interface{}{
		"secret_type": graphqlTokenType,
		"user_id":     "usr_orphan",
	}})
	if err == nil || !strings.Contains(err.Error(), "manually") {
		t.Fatalf("expected loud manual-cleanup error, got %v", err)
	}
}

func TestTokenRenew(t *testing.T) {
	mock := newMockGraphQL(t)
	b, s := getTestBackend(t)
	configureBackend(t, b, s, mock)
	writeRole(t, b, s, "test", "admin", 300, 3600)
	resp := readCreds(t, b, s, "test")

	renewed, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RenewOperation,
		Storage:   s,
		Secret:    resp.Secret,
	})
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if renewed == nil || renewed.Secret == nil {
		t.Fatalf("renew returned no secret")
	}
	if renewed.Secret.TTL != 300*time.Second {
		t.Errorf("renewed TTL = %s, want 5m0s", renewed.Secret.TTL)
	}
	if renewed.Secret.MaxTTL != 3600*time.Second {
		t.Errorf("renewed MaxTTL = %s, want 1h0m0s", renewed.Secret.MaxTTL)
	}
}

func TestTokenRenewRoleDeleted(t *testing.T) {
	mock := newMockGraphQL(t)
	b, s := getTestBackend(t)
	configureBackend(t, b, s, mock)
	writeRole(t, b, s, "test", "admin", 300, 3600)
	resp := readCreds(t, b, s, "test")

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "role/test",
		Storage:   s,
	}); err != nil {
		t.Fatalf("deleting role: %v", err)
	}

	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RenewOperation,
		Storage:   s,
		Secret:    resp.Secret,
	})
	if err == nil || !strings.Contains(err.Error(), "no longer exists") {
		t.Fatalf("expected role-gone renewal error, got %v", err)
	}
}

func TestInternalString(t *testing.T) {
	// No secret on the request: tolerate, return "".
	if got := internalString(&logical.Request{}, "anything"); got != "" {
		t.Errorf("internalString with nil secret = %q, want \"\"", got)
	}

	req := &logical.Request{Secret: &logical.Secret{InternalData: map[string]interface{}{
		"str":     "value",
		"num":     float64(7), // JSON round-trips numbers as float64
		"nilval":  nil,
		"untyped": 42,
	}}}
	cases := map[string]string{
		"str":     "value",
		"num":     "7",
		"nilval":  "",
		"untyped": "42",
		"missing": "",
	}
	for key, want := range cases {
		if got := internalString(req, key); got != want {
			t.Errorf("internalString(%q) = %q, want %q", key, got, want)
		}
	}
}
