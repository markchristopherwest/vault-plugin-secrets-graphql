package secretsengine

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Factory builds, configures, and returns the GraphQL secrets backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	b.Logger().Info("graphql secrets backend initialized")
	return b, nil
}

// graphqlBackend extends the Vault backend and caches the upstream API client.
type graphqlBackend struct {
	*framework.Backend
	lock   sync.RWMutex
	client *graphqlClient
}

// backend wires every path and the issued-token secret type into a single
// framework.Backend. All paths share one backend instance, so they read the
// same config, role storage, credential storage, and cached client.
func backend() *graphqlBackend {
	b := &graphqlBackend{}

	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(backendHelp),
		BackendType: logical.TypeLogical,
		Invalidate:  b.invalidate,
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				// config holds the admin password and session token; token/
				// records hold the raw minted JWTs.
				configStoragePath,
				roleStoragePrefix + "*",
				tokenStoragePrefix + "*",
			},
		},
		Paths: framework.PathAppend(
			pathRole(b),
			pathCredentials(b),
			[]*framework.Path{
				pathConfig(b),
			},
		),
		// Registering the secret type attaches the Revoke/Renew callbacks to
		// every leased token handed out via b.Secret(graphqlTokenType) in
		// credentialResponse (path_credentials.go), so leases are revoked on
		// expiry. Each issued token is also recorded under token/<token_id>
		// for inspect/list/delete.
		Secrets: []*framework.Secret{
			b.graphqlToken(),
		},
	}
	return b
}

// reset drops the cached client so the next caller rebuilds it from the
// freshly written (or freshly cleared) configuration.
func (b *graphqlBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.client = nil
	b.Logger().Debug("cleared cached graphql client")
}

// invalidate fires when watched storage changes (including on performance
// secondaries). A config change means the cached client is stale.
func (b *graphqlBackend) invalidate(ctx context.Context, key string) {
	if key == configStoragePath {
		b.Logger().Info("configuration changed; invalidating cached client")
		b.reset()
	}
}

// getClient returns the cached client, building it once from stored config.
// Construction is pure (no network I/O under the lock); the session is
// established lazily by getSession.
func (b *graphqlBackend) getClient(ctx context.Context, s logical.Storage) (*graphqlClient, error) {
	b.lock.RLock()
	unlockFunc := b.lock.RUnlock
	defer func() { unlockFunc() }()

	// Fast path: a client is already built.
	if b.client != nil {
		return b.client, nil
	}

	// Upgrade to a write lock to build the client.
	b.lock.RUnlock()
	b.lock.Lock()
	unlockFunc = b.lock.Unlock

	// Re-check: another goroutine may have built the client between dropping
	// the read lock and taking the write lock. Without this, concurrent
	// first-time callers each build and cache-overwrite a client, leaking the
	// discarded client's idle connection pool.
	if b.client != nil {
		return b.client, nil
	}

	config, err := getConfig(ctx, s)
	if err != nil {
		b.Logger().Error("failed to load configuration while building client", "error", err)
		return nil, err
	}
	if config == nil {
		b.Logger().Warn("client requested before backend was configured")
		return nil, errors.New("graphql backend is not configured: write config/ first")
	}

	// newClient seeds the client's session token from config.Token, so a
	// session persisted by getSession survives client rebuilds and plugin
	// restarts.
	client, err := newClient(config)
	if err != nil {
		b.Logger().Error("failed to build graphql client", "url", config.URL, "error", err)
		return nil, err
	}
	// Give the client the backend's logger so every upstream operation —
	// including full query documents at debug — is traced under this mount.
	client.logger = b.Logger().Named("client")

	b.client = client
	b.Logger().Info("built graphql API client", "url", config.URL)
	return b.client, nil
}

// getSession returns the client plus a verified admin session token. When the
// client had to mint a fresh token (first use, expiry, restart with a stale
// stored token), the new token is written back to config storage — that is
// how "the token secret from config" is stored in the backend. Persistence is
// best-effort: on a performance standby with read-only storage the session
// still works for this request, it just isn't durable.
func (b *graphqlBackend) getSession(ctx context.Context, s logical.Storage) (*graphqlClient, string, error) {
	client, err := b.getClient(ctx, s)
	if err != nil {
		return nil, "", err
	}

	token, refreshed, err := client.ensureSession(ctx)
	if err != nil {
		return nil, "", err
	}
	if refreshed {
		if perr := setConfigToken(ctx, s, token); perr != nil {
			b.Logger().Warn("failed to persist session token to config storage", "error", perr)
		} else {
			b.Logger().Info("persisted session token to config storage")
		}
	}
	return client, token, nil
}

// backendHelp should contain help information for the backend
const backendHelp = `
The GraphQL secrets backend dynamically generates user tokens (JWTs)
for the GraphQL products API. After mounting this backend, credentials
to manage GraphQL user tokens must be configured with the "config/"
endpoint.
`
