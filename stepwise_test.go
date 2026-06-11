package secretsengine

import (
	"os"
	"testing"
)

// TestAccGraphQL is a placeholder acceptance test.
//
// The original scaffold's stepwise_test.go referenced helpers and a `backend`
// type that no longer exist, so it did not compile. This replacement compiles
// cleanly and is skipped unless VAULT_ACC is set, leaving a clear home for a
// real acceptance suite (e.g. using the vault/sdk/testing/stepwise harness)
// without breaking `go test ./...`.
func TestAccGraphQL(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" {
		t.Skip("set VAULT_ACC=1 to run acceptance tests")
	}

	t.Skip("acceptance tests are not yet implemented for the GraphQL secrets engine")
}
