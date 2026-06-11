package secretsengine

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

// failPutStorage wraps a storage view and fails every Put whose key matches
// failPrefix, simulating storage loss exactly between upstream provisioning
// and record persistence.
type failPutStorage struct {
	logical.Storage
	failPrefix string
}

func (f *failPutStorage) Put(ctx context.Context, entry *logical.StorageEntry) error {
	if strings.HasPrefix(entry.Key, f.failPrefix) {
		return fmt.Errorf("synthetic storage failure for key %q", entry.Key)
	}
	return f.Storage.Put(ctx, entry)
}

func TestCredsUnknownRole(t *testing.T) {
	b, s := getTestBackend(t)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/does-not-exist",
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected ErrorResponse for unknown role, got %#v", resp)
	}
	if msg := resp.Error().Error(); !strings.Contains(msg, "not found") {
		t.Errorf("error = %q, want it to mention not found", msg)
	}
}

func TestCredsReadIssuesLeasedSecret(t *testing.T) {
	ctx := context.Background()
	mock := newMockGraphQL(t)
	b, s := getTestBackend(t)
	configureBackend(t, b, s, mock)
	writeRole(t, b, s, "test", "admin", 300, 3600)

	resp := readCreds(t, b, s, "test")
	if resp.Secret == nil {
		t.Fatalf("creds read returned no lease; Secrets registration or credentialResponse is broken")
	}
	if resp.Secret.TTL != 300*time.Second {
		t.Errorf("lease TTL = %s, want 5m0s", resp.Secret.TTL)
	}
	if resp.Secret.MaxTTL != 3600*time.Second {
		t.Errorf("lease MaxTTL = %s, want 1h0m0s", resp.Secret.MaxTTL)
	}

	token, _ := resp.Data["token"].(string)
	if token == "" {
		t.Errorf("issued credential has empty token")
	}
	saName, _ := resp.Data["username"].(string)
	if !strings.HasPrefix(saName, "vault-admin-") {
		t.Errorf("service account name = %q, want vault-admin-<id> form", saName)
	}
	if userID, _ := resp.Data["user_id"].(string); !strings.HasPrefix(userID, "sa_") {
		t.Errorf("user_id = %q, want upstream sa_-prefixed string id", resp.Data["user_id"])
	}
	if roleName, _ := resp.Data["role"].(string); roleName != "test" {
		t.Errorf("role = %q, want test", roleName)
	}
	if !mock.hasSA(saName) {
		t.Errorf("service account %q not provisioned upstream", saName)
	}

	// InternalData must carry everything revoke needs.
	for _, key := range []string{"username", "token_id", "account_type", "role"} {
		if v := internalString(&logical.Request{Secret: resp.Secret}, key); v == "" {
			t.Errorf("InternalData missing %q; revocation would be lossy", key)
		}
	}

	// And the minted secret must be recorded under token/<token_id>.
	tokenID := resp.Data["token_id"].(string)
	entry, err := s.Get(ctx, tokenStoragePrefix+tokenID)
	if err != nil {
		t.Fatalf("storage get: %v", err)
	}
	if entry == nil {
		t.Fatalf("no credential record at token/%s", tokenID)
	}
	var record credRecord
	if err := entry.DecodeJSON(&record); err != nil {
		t.Fatalf("decoding record: %v", err)
	}
	if record.Token != token {
		t.Errorf("recorded token differs from issued token")
	}
	if record.AccountType != accountTypeServiceAccount {
		t.Errorf("recorded account_type = %q, want %q", record.AccountType, accountTypeServiceAccount)
	}
}

// TestCredsEachReadMintsDistinctCredential: creds reads are generate actions,
// never idempotent — two reads must produce two upstream accounts and two
// distinct tokens.
func TestCredsEachReadMintsDistinctCredential(t *testing.T) {
	mock := newMockGraphQL(t)
	b, s := getTestBackend(t)
	configureBackend(t, b, s, mock)
	writeRole(t, b, s, "test", "admin", 300, 3600) // mints credential #1

	r1 := readCreds(t, b, s, "test") // #2
	r2 := readCreds(t, b, s, "test") // #3

	if r1.Data["token"] == r2.Data["token"] {
		t.Errorf("two creds reads returned the same token")
	}
	if r1.Data["username"] == r2.Data["username"] {
		t.Errorf("two creds reads returned the same upstream account")
	}
	if got := mock.saCount(); got != 3 {
		t.Errorf("upstream service account count = %d, want 3 (role write + 2 reads)", got)
	}
}

func TestTokenRecordLifecycle(t *testing.T) {
	ctx := context.Background()
	mock := newMockGraphQL(t)
	b, s := getTestBackend(t)
	configureBackend(t, b, s, mock)
	writeRole(t, b, s, "test", "admin", 300, 3600)
	resp := readCreds(t, b, s, "test")
	tokenID := resp.Data["token_id"].(string)

	// LIST token/ includes the id.
	listResp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation,
		Path:      "token/",
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("listing tokens: %v", err)
	}
	keys, _ := listResp.Data["keys"].([]string)
	found := false
	for _, k := range keys {
		if k == tokenID {
			found = true
		}
	}
	if !found {
		t.Fatalf("token list %v does not contain %q", keys, tokenID)
	}

	// GET token/<id> returns metadata but never the raw token.
	readResp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "token/" + tokenID,
		Storage:   s,
	})
	if err != nil || readResp == nil {
		t.Fatalf("reading token record: resp=%#v err=%v", readResp, err)
	}
	if got := readResp.Data["role"]; got != "test" {
		t.Errorf("record role = %v, want test", got)
	}
	if got := readResp.Data["account_type"]; got != accountTypeServiceAccount {
		t.Errorf("record account_type = %v, want %v", got, accountTypeServiceAccount)
	}
	if _, ok := readResp.Data["token"]; ok {
		t.Errorf("raw token re-served on token/ read; it must stay lease-gated")
	}

	// DELETE token/<id> drops only the record — upstream account survives
	// (revocation belongs to the lease lifecycle).
	saName := resp.Data["username"].(string)
	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "token/" + tokenID,
		Storage:   s,
	}); err != nil {
		t.Fatalf("deleting token record: %v", err)
	}
	entry, err := s.Get(ctx, tokenStoragePrefix+tokenID)
	if err != nil {
		t.Fatalf("storage get: %v", err)
	}
	if entry != nil {
		t.Errorf("token record survived delete")
	}
	if !mock.hasSA(saName) {
		t.Errorf("token record delete revoked the upstream account; it must not")
	}
}

// TestIssuePersistFailureRollsBack: if the token/ record can't be written,
// the freshly provisioned upstream account must be torn down so the backend
// never holds credentials Vault can't account for.
func TestIssuePersistFailureRollsBack(t *testing.T) {
	mock := newMockGraphQL(t)
	b, s := getTestBackend(t)
	configureBackend(t, b, s, mock)
	writeRole(t, b, s, "test", "admin", 300, 3600)

	before := mock.saCount()
	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test",
		Storage:   &failPutStorage{Storage: s, failPrefix: tokenStoragePrefix},
	})
	if err == nil || !strings.Contains(err.Error(), "persisting credential record") {
		t.Fatalf("expected persistence error, got %v", err)
	}
	if got := mock.saCount(); got != before {
		t.Errorf("upstream service accounts leaked on persist failure: %d -> %d", before, got)
	}
}
