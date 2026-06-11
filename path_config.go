package secretsengine

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const configStoragePath = "config"

// graphqlConfig includes the minimum configuration required to instantiate a
// new graphql client, plus the session token obtained with those credentials.
// The token is written back to this storage entry by backend.getSession so
// the session survives client rebuilds and plugin restarts; it is never
// returned on read.
type graphqlConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
	URL      string `json:"url"`
	Token    string `json:"token,omitempty"`
}

// pathConfig extends the Vault API with a `/config` endpoint.
// password is marked sensitive and is never returned on read.
func pathConfig(b *graphqlBackend) *framework.Path {
	return &framework.Path{
		Pattern: configStoragePath,
		Fields: map[string]*framework.FieldSchema{
			"username": {
				Type:        framework.TypeString,
				Description: "The username to access the GraphQL products API",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Username",
				},
			},
			"password": {
				Type:        framework.TypeString,
				Description: "The user's password to access the GraphQL products API",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Password",
					Sensitive: true,
				},
			},
			"url": {
				Type:        framework.TypeString,
				Description: "The URL for the GraphQL products API",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "URL",
				},
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathConfigRead},
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathConfigDelete},
		},
		ExistenceCheck:  b.pathConfigExistenceCheck,
		HelpSynopsis:    pathConfigHelpSynopsis,
		HelpDescription: pathConfigHelpDescription,
	}
}

// pathConfigExistenceCheck verifies whether the configuration exists, which
// lets Vault route a write to create vs. update.
func (b *graphqlBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}
	return out != nil, nil
}

func (b *graphqlBackend) pathConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		b.Logger().Error("failed to read configuration", "error", err)
		return nil, err
	}
	if config == nil {
		return nil, nil
	}
	// password and token are sensitive and intentionally omitted; we only
	// surface whether a session token is currently stored.
	return &logical.Response{Data: map[string]interface{}{
		"username":          config.Username,
		"url":               config.URL,
		"has_session_token": config.Token != "",
	}}, nil
}

func (b *graphqlBackend) pathConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	logger := b.Logger().With("operation", req.Operation)

	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		logger.Error("failed to read existing configuration", "error", err)
		return nil, err
	}

	if config == nil {
		if req.Operation == logical.UpdateOperation {
			logger.Warn("update requested but no configuration exists")
			return nil, errors.New("config not found during update operation")
		}
		config = new(graphqlConfig)
	}

	if username, ok := d.GetOk("username"); ok {
		config.Username = username.(string)
	} else if req.Operation == logical.CreateOperation {
		return nil, errors.New("missing username in configuration")
	}
	if rawURL, ok := d.GetOk("url"); ok {
		config.URL = rawURL.(string)
	} else if req.Operation == logical.CreateOperation {
		return nil, errors.New("missing url in configuration")
	}
	if password, ok := d.GetOk("password"); ok {
		config.Password = password.(string)
	} else if req.Operation == logical.CreateOperation {
		return nil, errors.New("missing password in configuration")
	}

	// Any credential/URL change invalidates the stored session; clear it so
	// the next getSession logs in fresh instead of presenting a token minted
	// against the old configuration.
	config.Token = ""

	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		logger.Error("failed to encode configuration", "error", err)
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		logger.Error("failed to persist configuration", "error", err)
		return nil, err
	}

	// Rebuild the client from the new configuration on the next request.
	b.reset()
	logger.Info("configuration written; cached client reset", "username", config.Username, "url", config.URL)
	return nil, nil
}

func (b *graphqlBackend) pathConfigDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, configStoragePath); err != nil {
		b.Logger().Error("failed to delete configuration", "error", err)
		return nil, err
	}
	b.reset()
	b.Logger().Info("configuration deleted; cached client reset")
	return nil, nil
}

func getConfig(ctx context.Context, s logical.Storage) (*graphqlConfig, error) {
	entry, err := s.Get(ctx, configStoragePath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	config := new(graphqlConfig)
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, fmt.Errorf("error reading root configuration: %w", err)
	}
	return config, nil
}

// setConfigToken persists the client's session token alongside the backend
// configuration so it can be reused after a client rebuild or plugin restart.
// Best-effort from the caller's perspective: getSession logs and continues if
// this fails (e.g. read-only storage on a performance standby).
func setConfigToken(ctx context.Context, s logical.Storage, token string) error {
	config, err := getConfig(ctx, s)
	if err != nil {
		return err
	}
	if config == nil {
		return nil
	}

	config.Token = token
	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}

// pathConfigHelpSynopsis summarizes the help text for the configuration
const pathConfigHelpSynopsis = `Configure the graphql backend.`

// pathConfigHelpDescription describes the help text for the configuration
const pathConfigHelpDescription = `
The graphql secret backend requires credentials for managing
JWTs issued to users working with the products API.

You must sign up with a username and password and
specify the graphql address for the products API
before using this secrets backend.
`
