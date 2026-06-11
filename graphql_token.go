package secretsengine

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const graphqlTokenType = "graphql_token"

// graphqlToken is the credential minted by issueRoleCreds. UserID is a string
// because the server issues prefixed ids ("usr_...").
type graphqlToken struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	TokenID  string `json:"token_id"`
	Token    string `json:"token"`
}

// graphqlToken defines the leased secret returned by role/<name> writes and
// creds/<name> reads. Registering it in backend.go's Secrets slice is what
// makes Vault attach a lease_id and drive Renew/Revoke.
func (b *graphqlBackend) graphqlToken() *framework.Secret {
	return &framework.Secret{
		Type: graphqlTokenType,
		Fields: map[string]*framework.FieldSchema{
			"token": {
				Type:        framework.TypeString,
				Description: "JWT minted by the GraphQL server for a dynamic user",
			},
			"username": {
				Type:        framework.TypeString,
				Description: "Upstream username of the dynamic user",
			},
			"user_id": {
				Type:        framework.TypeString,
				Description: "Upstream id of the dynamic user",
			},
			"token_id": {
				Type:        framework.TypeString,
				Description: "Backend-local id the credential is recorded under (token/<token_id>)",
			},
		},
		Renew:  b.tokenRenew,
		Revoke: b.tokenRevoke,
	}
}

// internalString pulls a string value out of the lease's InternalData,
// tolerating absent keys (older leases) and non-string JSON round-trips.
func internalString(req *logical.Request, key string) string {
	if req.Secret == nil {
		return ""
	}
	if v, ok := req.Secret.InternalData[key]; ok && v != nil {
		return fmt.Sprintf("%v", v)
	}
	return ""
}

// tokenRevoke tears down the credential behind a lease by deleting the
// upstream account (service account for current leases, dynamic user for
// leases minted by older builds), then removing the token/<token_id> record.
//
// Server contract notes:
//   - deleteServiceAccount/deleteUser are keyed by NAME/USERNAME (not id)
//     and are idempotent upstream, so retried revocations succeed.
//   - There is no signout mutation. The server's JWTs are stateless (24h
//     exp), so account deletion is the strongest teardown available; the
//     issued token itself only fully dies at exp.
//
// Hardening: upstream 401/403/unauthorized/not-found errors mean the
// credential is already gone and are treated as successful revocation —
// returning an error there would wedge Vault's revocation queue into retrying
// an impossible operation forever. Genuine outages still return errors so
// Vault retries.
func (b *graphqlBackend) tokenRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	tokenID := internalString(req, "token_id")
	userID := internalString(req, "user_id")
	username := internalString(req, "username")
	accountType := internalString(req, "account_type")
	logger := b.Logger().With("token_id", tokenID, "user_id", userID,
		"username", username, "account_type", accountType)

	client, session, err := b.getSession(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("error getting client session: %w", err)
	}

	// 1. Delete the upstream account behind the lease. New leases are
	//    service accounts (deleted by name); leases minted by older builds
	//    carry account_type "user" (or nothing) and go through deleteUser.
	switch {
	case username != "" && accountType == accountTypeServiceAccount:
		if err := client.DeleteServiceAccount(ctx, session, username); err != nil {
			if isCredentialGone(err) {
				logger.Debug("service account already gone upstream; treating revoke as complete", "error", err)
			} else {
				return nil, fmt.Errorf("error deleting service account %q: %w", username, err)
			}
		}
	case username != "":
		if err := client.DeleteUser(ctx, session, username); err != nil {
			if isCredentialGone(err) {
				logger.Debug("dynamic user already gone upstream; treating revoke as complete", "error", err)
			} else {
				return nil, fmt.Errorf("error deleting dynamic user %q: %w", username, err)
			}
		}
	case userID != "":
		// A lease minted before username/name was recorded in InternalData
		// cannot be revoked upstream: the server only deletes by name and has
		// no lookup-by-id. Fail loudly so the operator cleans it up rather
		// than silently leaking the account.
		return nil, fmt.Errorf("lease for id %q has no account name in internal data; delete the upstream account manually", userID)
	default:
		logger.Debug("lease carries no upstream identity; nothing to revoke server-side")
	}

	// 2. Drop the stored record. Failure here must not wedge revocation —
	//    the upstream credential is dead; the stale record is only cosmetic.
	if tokenID != "" {
		if err := req.Storage.Delete(ctx, tokenStoragePrefix+tokenID); err != nil {
			logger.Warn("failed to delete credential record after revoke", "error", err)
		}
	}

	logger.Info("revoked leased credential")
	return nil, nil
}

// tokenRenew extends the lease using the role's TTL/MaxTTL.
func (b *graphqlBackend) tokenRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := internalString(req, "role")
	if roleName == "" {
		return nil, fmt.Errorf("secret is missing role internal data")
	}

	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}
	if role == nil {
		return nil, fmt.Errorf("error retrieving role: role %q no longer exists", roleName)
	}

	b.Logger().Debug("renewing lease", "role", roleName,
		"ttl", role.TTL.String(), "max_ttl", role.MaxTTL.String())

	resp := &logical.Response{Secret: req.Secret}
	if role.TTL > 0 {
		resp.Secret.TTL = role.TTL
	}
	if role.MaxTTL > 0 {
		resp.Secret.MaxTTL = role.MaxTTL
	}
	return resp, nil
}
