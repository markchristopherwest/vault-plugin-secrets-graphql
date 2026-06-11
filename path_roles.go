package secretsengine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const roleStoragePrefix = "role/"

// graphqlRoleEntry defines the data required for a Vault role to mint graphql
// tokens. Per-lease credentials (token, user id) are deliberately NOT stored
// on the role — every issuance is recorded under token/<token_id> instead
// (path_credentials.go), so concurrent leases don't clobber each other.
type graphqlRoleEntry struct {
	Username string        `json:"username"`
	TTL      time.Duration `json:"ttl"`
	MaxTTL   time.Duration `json:"max_ttl"`
}

// toResponseData returns response data for a role
func (r *graphqlRoleEntry) toResponseData() map[string]interface{} {
	return map[string]interface{}{
		"username": r.Username,
		"ttl":      r.TTL.Seconds(),
		"max_ttl":  r.MaxTTL.Seconds(),
	}
}

// pathRole extends the Vault API with a `/role` endpoint for the backend,
// plus a list path for all roles.
func pathRole(b *graphqlBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "role/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the role",
					Required:    true,
				},
				"username": {
					Type:        framework.TypeString,
					Description: "The graphql account username this role provisions tokens for",
					Required:    true,
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Default lease for generated credentials. If not set or set to 0, will use system default.",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Maximum time for role. If not set or set to 0, will use system default.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathRolesRead,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathRolesWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRolesWrite,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRolesDelete,
				},
			},
			// Required because CreateOperation is registered: the framework
			// calls this to route an incoming write to create vs. update.
			// Without it, role writes fail with "existence check not found
			// for path".
			ExistenceCheck:  b.pathRolesExistenceCheck,
			HelpSynopsis:    pathRoleHelpSynopsis,
			HelpDescription: pathRoleHelpDescription,
		},
		{
			Pattern: "role/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathRolesList,
				},
			},
			HelpSynopsis:    pathRoleListHelpSynopsis,
			HelpDescription: pathRoleListHelpDescription,
		},
	}
}

// pathRolesExistenceCheck reports whether the named role already exists,
// letting Vault route a write to CreateOperation vs. UpdateOperation. It
// reuses getRole so a corrupt entry surfaces here as an error instead of
// silently routing every write to create.
func (b *graphqlBackend) pathRolesExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	role, err := b.getRole(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}
	return role != nil, nil
}

// getRole gets the role from the Vault storage API
func (b *graphqlBackend) getRole(ctx context.Context, s logical.Storage, name string) (*graphqlRoleEntry, error) {
	if name == "" {
		return nil, errors.New("missing role name")
	}

	entry, err := s.Get(ctx, roleStoragePrefix+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var role graphqlRoleEntry
	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}
	return &role, nil
}

// setRole adds the role to the Vault storage API
func setRole(ctx context.Context, s logical.Storage, name string, roleEntry *graphqlRoleEntry) error {
	entry, err := logical.StorageEntryJSON(roleStoragePrefix+name, roleEntry)
	if err != nil {
		return err
	}
	if entry == nil {
		return errors.New("failed to create storage entry for role")
	}
	return s.Put(ctx, entry)
}

// pathRolesList makes a request to Vault storage to retrieve a list of roles
func (b *graphqlBackend) pathRolesList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, roleStoragePrefix)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(entries), nil
}

// pathRolesRead makes a request to Vault storage to read a role and return response data
func (b *graphqlBackend) pathRolesRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entry, err := b.getRole(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	return &logical.Response{Data: entry.toResponseData()}, nil
}

// pathRolesWrite persists the role, then immediately mints a credential
// through issueRoleCreds — the same path creds/<role> reads use — records it
// under token/<token_id>, and returns it as a leased secret. Writing a role
// therefore both saves the definition and hands back a working, lease_id-
// bearing token in one call.
func (b *graphqlBackend) pathRolesWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	nameRaw, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("missing role name"), nil
	}
	name := nameRaw.(string)
	logger := b.Logger().With("role", name, "operation", req.Operation)

	roleEntry, err := b.getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if roleEntry == nil {
		roleEntry = &graphqlRoleEntry{}
	}

	createOperation := req.Operation == logical.CreateOperation

	if username, ok := d.GetOk("username"); ok {
		roleEntry.Username = username.(string)
	} else if createOperation {
		return nil, fmt.Errorf("missing username in role")
	}

	if ttlRaw, ok := d.GetOk("ttl"); ok {
		roleEntry.TTL = time.Duration(ttlRaw.(int)) * time.Second
	}

	if maxTTLRaw, ok := d.GetOk("max_ttl"); ok {
		roleEntry.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second
	}

	if roleEntry.MaxTTL != 0 && roleEntry.TTL > roleEntry.MaxTTL {
		return logical.ErrorResponse("ttl cannot be greater than max_ttl"), nil
	}

	if err := setRole(ctx, req.Storage, name, roleEntry); err != nil {
		return nil, err
	}
	logger.Info("role written", "username", roleEntry.Username,
		"ttl", roleEntry.TTL.String(), "max_ttl", roleEntry.MaxTTL.String())

	// Mint, store, and lease a credential as part of the write. The role
	// definition above is already persisted, so an issuance failure leaves a
	// usable role behind — creds/<role> can be read once the upstream
	// recovers.
	tok, err := b.issueRoleCreds(ctx, req, name, roleEntry)
	if err != nil {
		return nil, fmt.Errorf("role %q saved, but credential issuance failed: %w", name, err)
	}
	return b.credentialResponse(name, roleEntry, tok), nil
}

// pathRolesDelete makes a request to Vault storage to delete a role
func (b *graphqlBackend) pathRolesDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if err := req.Storage.Delete(ctx, roleStoragePrefix+name); err != nil {
		return nil, fmt.Errorf("error deleting graphql role: %w", err)
	}
	b.Logger().Info("role deleted", "role", name)
	return nil, nil
}

const (
	pathRoleHelpSynopsis    = `Manages the Vault role for generating graphql tokens.`
	pathRoleHelpDescription = `
This path allows you to read and write roles used to generate graphql tokens.
You can configure a role to manage a user's token by setting the username field.
Writing a role also mints an initial leased credential and records it under
token/<token_id>.
`

	pathRoleListHelpSynopsis    = `List the existing roles in graphql backend`
	pathRoleListHelpDescription = `Roles will be listed by the role name.`
)
