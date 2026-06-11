package secretsengine

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	// tokenStoragePrefix is where every minted credential is recorded so
	// issued secrets can be listed/inspected/deleted via token/. It is
	// distinct from the creds/<role> API path (which mints) and is
	// seal-wrapped in backend.go because the record includes the live JWT.
	tokenStoragePrefix = "token/"

	accountTypeUser           = "user"
	accountTypeServiceAccount = "service_account"
)

// credRecord is the stored copy of a minted credential, keyed by TokenID.
// The raw token is persisted (per requirement: minted secrets are stored in
// the backend) under seal-wrapped storage. Username holds the upstream
// account name (service account name for new leases); UserID the upstream id.
type credRecord struct {
	Role        string    `json:"role"`
	Username    string    `json:"username"`
	UserID      string    `json:"user_id"`
	TokenID     string    `json:"token_id"`
	Token       string    `json:"token"`
	AccountType string    `json:"account_type"`
	IssuedAt    time.Time `json:"issued_at"`
}

// pathCredentials extends the Vault API with:
//
//	creds/<role>      read   -> mint a new leased credential for the role
//	token/            list   -> token ids of every recorded credential
//	token/<token_id>  read   -> inspect a recorded credential
//	token/<token_id>  delete -> drop the record (does not revoke upstream;
//	                            revocation belongs to the lease lifecycle)
func pathCredentials(b *graphqlBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "creds/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the role to mint credentials for",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathCredentialsRead,
				},
			},
			HelpSynopsis:    pathCredsHelpSynopsis,
			HelpDescription: pathCredsHelpDescription,
		},
		{
			Pattern: "token/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathTokensList,
				},
			},
			HelpSynopsis:    pathTokenListHelpSynopsis,
			HelpDescription: pathTokenListHelpDescription,
		},
		{
			Pattern: "token/" + framework.GenericNameRegex("token_id"),
			Fields: map[string]*framework.FieldSchema{
				"token_id": {
					Type:        framework.TypeString,
					Description: "ID of the issued token record",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathTokensRead,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathTokensDelete,
				},
			},
			HelpSynopsis:    pathTokenHelpSynopsis,
			HelpDescription: pathTokenHelpDescription,
		},
	}
}

// issueRoleCreds is the single credential-issuance path, used by both role
// writes (path_roles.go) and creds/<role> reads. Authorized by the stored
// config session token, it provisions a uniquely named SERVICE ACCOUNT whose
// token the server mints at creation, and records the result under
// token/<token_id> before returning. The returned token is the service
// account's — CreateServiceAccount hard-fails if the server hands back the
// session token or a token belonging to any other identity.
func (b *graphqlBackend) issueRoleCreds(ctx context.Context, req *logical.Request, roleName string, role *graphqlRoleEntry) (*graphqlToken, error) {
	logger := b.Logger().With("role", roleName)

	client, session, err := b.getSession(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("error getting client session: %w", err)
	}

	id, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("generating credential id: %w", err)
	}

	// vault-<role-username>-<short id> keeps upstream accounts attributable
	// to the role while staying unique per lease.
	name := fmt.Sprintf("vault-%s-%s", role.Username, id[:8])
	logger.Debug("minting dynamic credential", "service_account", name)

	auth, err := client.CreateServiceAccount(ctx, session, name)
	if err != nil {
		return nil, fmt.Errorf("provisioning service account for role %q: %w", roleName, err)
	}

	tok := &graphqlToken{
		UserID:   auth.UserID,
		Username: auth.Username,
		TokenID:  id,
		Token:    auth.Token,
	}

	// Record the minted secret. If persistence fails, best-effort tear down
	// the upstream account so we never hold credentials Vault can't account
	// for.
	record := &credRecord{
		Role:        roleName,
		Username:    tok.Username,
		UserID:      tok.UserID,
		TokenID:     tok.TokenID,
		Token:       tok.Token,
		AccountType: accountTypeServiceAccount,
		IssuedAt:    time.Now().UTC(),
	}
	entry, err := logical.StorageEntryJSON(tokenStoragePrefix+tok.TokenID, record)
	if err == nil {
		err = req.Storage.Put(ctx, entry)
	}
	if err != nil {
		logger.Error("failed to persist credential record; rolling back upstream service account",
			"token_id", tok.TokenID, "error", err)
		if delErr := client.DeleteServiceAccount(ctx, session, tok.Username); delErr != nil && !isCredentialGone(delErr) {
			logger.Error("rollback of upstream service account failed; manual cleanup required",
				"service_account", tok.Username, "error", delErr)
		}
		return nil, fmt.Errorf("persisting credential record: %w", err)
	}

	logger.Info("issued dynamic credential",
		"token_id", tok.TokenID, "id", tok.UserID, "service_account", tok.Username)
	return tok, nil
}

// credentialResponse wraps a minted token in the registered secret type so
// Vault attaches a lease_id and drives Renew/Revoke. Shared by role writes
// and creds/<role> reads so both return identical leased secrets.
func (b *graphqlBackend) credentialResponse(roleName string, role *graphqlRoleEntry, tok *graphqlToken) *logical.Response {
	resp := b.Secret(graphqlTokenType).Response(
		// Returned to the caller.
		map[string]interface{}{
			"token":    tok.Token,
			"username": tok.Username,
			"user_id":  tok.UserID,
			"token_id": tok.TokenID,
			"role":     roleName,
		},
		// InternalData: everything Revoke/Renew need, keyed by lease.
		// account_type routes revocation to deleteServiceAccount; leases
		// minted by older builds carry "user" (or nothing) and still revoke
		// through deleteUser.
		map[string]interface{}{
			"token":        tok.Token,
			"username":     tok.Username,
			"user_id":      tok.UserID,
			"token_id":     tok.TokenID,
			"role":         roleName,
			"account_type": accountTypeServiceAccount,
		},
	)
	if role.TTL > 0 {
		resp.Secret.TTL = role.TTL
	}
	if role.MaxTTL > 0 {
		resp.Secret.MaxTTL = role.MaxTTL
	}
	return resp
}

// pathCredentialsRead mints a leased credential for the named role.
func (b *graphqlBackend) pathCredentialsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("name").(string)

	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}
	if role == nil {
		return logical.ErrorResponse("role %q not found", roleName), nil
	}

	tok, err := b.issueRoleCreds(ctx, req, roleName, role)
	if err != nil {
		return nil, err
	}
	return b.credentialResponse(roleName, role, tok), nil
}

// pathTokensList lists the ids of every recorded credential.
func (b *graphqlBackend) pathTokensList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, tokenStoragePrefix)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(entries), nil
}

// pathTokensRead returns a recorded credential's metadata. The raw token is
// intentionally omitted: it was returned once at issue time and lives in
// seal-wrapped storage; re-serving it here would bypass the lease. Add
// "token": record.Token below if you explicitly want it readable.
func (b *graphqlBackend) pathTokensRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	id := d.Get("token_id").(string)

	entry, err := req.Storage.Get(ctx, tokenStoragePrefix+id)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var record credRecord
	if err := entry.DecodeJSON(&record); err != nil {
		return nil, fmt.Errorf("decoding credential record %q: %w", id, err)
	}
	return &logical.Response{Data: map[string]interface{}{
		"role":         record.Role,
		"username":     record.Username,
		"user_id":      record.UserID,
		"token_id":     record.TokenID,
		"account_type": record.AccountType,
		"issued_at":    record.IssuedAt.Format(time.RFC3339),
	}}, nil
}

// pathTokensDelete drops a credential record. Upstream revocation is the
// lease's job (vault lease revoke <lease_id>); this only removes bookkeeping.
func (b *graphqlBackend) pathTokensDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	id := d.Get("token_id").(string)
	if err := req.Storage.Delete(ctx, tokenStoragePrefix+id); err != nil {
		return nil, fmt.Errorf("error deleting credential record: %w", err)
	}
	b.Logger().Info("deleted credential record", "token_id", id)
	return nil, nil
}

const (
	pathCredsHelpSynopsis    = `Generate a GraphQL API token from a specific Vault role.`
	pathCredsHelpDescription = `
Reading creds/<role> provisions a service account on the GraphQL server,
authorized by the stored config session, and returns the token the server
minted for it as a leased Vault secret. Revoking the lease deletes the
service account.
`

	pathTokenListHelpSynopsis    = `List the ids of credentials minted by this backend.`
	pathTokenListHelpDescription = `Issued credentials are recorded by token_id when minted via role writes or creds/ reads.`

	pathTokenHelpSynopsis    = `Inspect or delete the record of an issued credential.`
	pathTokenHelpDescription = `
Reading token/<token_id> returns the stored metadata for a minted credential.
Deleting it removes only the record; use lease revocation to revoke upstream.
`
)
