package secretsengine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
)

// userAgent identifies this plugin in upstream request logs for auditing.
const userAgent = "Vault-Plugin-Secrets-GraphQL"

// graphqlClient talks to the GraphQL identity server (graphql-server-go). It
// is self-contained (stdlib net/http) and speaks the GraphQL-over-HTTP
// protocol the server's executor expects: every operation is a POST to a
// single endpoint carrying {"query": "<document>"} — no variables object, no
// operation name. The documents themselves live in graphql_operations.go;
// string arguments are filled into their %s slots via gqlString, which
// JSON-escapes values so they can never break out of the document.
//
// Server contract this client is shaped around:
//   - logIn returns ONLY a token; user identity is never part of the auth
//     payload, so SignUp takes id/username from createUser (Me as fallback).
//   - deleteUser is keyed by username and idempotent.
//   - There is no signout mutation: tokens are stateless 24h JWTs and user
//     deletion is the only teardown, so this client has no SignOut.
//
// The client keeps one admin session token (a JWT obtained by signing in as
// the configured root user). It is seeded from config.Token on construction so
// a session persisted by the backend survives client rebuilds and restarts,
// and refreshed lazily by ensureSession when it is empty or no longer valid.
type graphqlClient struct {
	URL        string
	Username   string
	Password   string
	HTTPClient *http.Client
	logger     hclog.Logger

	// sessionMu guards session so concurrent leases serialize on a single
	// login instead of stampeding the server with redundant authentications.
	sessionMu sync.Mutex
	session   string
}

// log returns a usable logger even when one was never injected (e.g. a client
// built directly in a test), so the request methods never nil-panic.
func (c *graphqlClient) log() hclog.Logger {
	if c.logger != nil {
		return c.logger
	}
	return hclog.NewNullLogger()
}

// newClient validates the configuration and returns a pooled, ready client.
// The backend injects a logger after construction (see getClient). The session
// token, if one was persisted to config, is seeded here so ensureSession can
// reuse it instead of logging in again.
func newClient(config *graphqlConfig) (*graphqlClient, error) {
	if config == nil {
		return nil, errors.New("client configuration was nil")
	}
	if config.Username == "" {
		return nil, errors.New("client username was not defined")
	}
	if config.Password == "" {
		return nil, errors.New("client password was not defined")
	}
	if config.URL == "" {
		return nil, errors.New("client URL was not defined")
	}

	// Fail fast: validate the URL on init instead of waiting for a network call.
	// parsedURL, err := url.ParseRequestURI(config.URL)
	// if err != nil {
	// return nil, fmt.Errorf("invalid client URL %q: %w", config.URL, err)
	// }
	// The server exposes a single GraphQL endpoint (/graphql). Accept either
	// the full endpoint ("https://host/graphql") or a bare host and default
	// the path, so an operator can configure URL either way.
	// if parsedURL.Path == "" || parsedURL.Path == "/" {
	// 	parsedURL.Path = "/graphql"
	// }

	// Connection pooling for concurrent leases. Do NOT assert
	// http.DefaultTransport.(*http.Transport) unconditionally: instrumentation
	// packages (otelhttp, etc.) pulled in transitively can replace that global
	// with a wrapper, and the bare assertion panics, taking the plugin process
	// down. Clone when it is the stdlib type; otherwise build a fresh transport.
	transport, ok := http.DefaultTransport.(*http.Transport)
	if ok {
		transport = transport.Clone() // inherit proxy/env defaults when available
	} else {
		transport = &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			ForceAttemptHTTP2:     true,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	}
	transport.MaxIdleConns = 100
	transport.MaxIdleConnsPerHost = 100
	transport.IdleConnTimeout = 90 * time.Second

	return &graphqlClient{
		URL:      config.URL,
		Username: config.Username,
		Password: config.Password,
		HTTPClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
		session: config.Token, // reuse a persisted session if present
	}, nil
}

// gqlString renders s as a GraphQL string literal. JSON's string encoding is a
// compatible subset of GraphQL's, so values are escaped (quotes, backslashes,
// control characters) and can be embedded in a query without breaking it.
func gqlString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		// Marshaling a string cannot fail; fall back to an empty literal.
		return `""`
	}
	return string(b)
}

// --- GraphQL response shapes ------------------------------------------------
//
// These map onto the selection sets in graphql_operations.go. Reshape an
// operation's selection and these structs together; nothing else needs to
// change.

type userPayload struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

// identityPayload absorbs either member of the server's Identity union
// (User { id username } | ServiceAccount { id name }) as selected by opMe.
type identityPayload struct {
	ID       string `json:"id"`
	Username string `json:"username"` // set when the identity is a User
	Name     string `json:"name"`     // set when the identity is a ServiceAccount
}

// authPayload mirrors the server's AuthPayload: ONLY a token. There is no
// user selection on sign-in; identity comes from createUser or me.
type authPayload struct {
	Token string `json:"token"`
}

type createUserData struct {
	CreateUser userPayload `json:"createUser"`
}

type logInData struct {
	SignIn authPayload `json:"login"`
}

type meData struct {
	Me identityPayload `json:"me"`
}

// serviceAccountPayload mirrors the ServiceAccount selection inside
// opCreateServiceAccount.
type serviceAccountPayload struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// createServiceAccountData maps opCreateServiceAccount's payload exactly:
//
//	createServiceAccount(name: ...) { serviceAccount { id name } secret }
//
// The minted credential is returned under the SECRET field (not "token" —
// decoding "token" here is the historical bug that made payload.Secret come
// back empty and trip the "returned no token" guard on every role write).
// Reshape this struct together with the document in graphql_operations.go;
// nothing else needs to change.
type createServiceAccountData struct {
	CreateServiceAccount struct {
		Secret         string                `json:"secret"`
		ServiceAccount serviceAccountPayload `json:"serviceAccount"`
	} `json:"createServiceAccount"`
}

// authResult is the outcome of provisioning a dynamic user: the upstream id and
// username plus the freshly minted JWT that becomes the leased credential.
type authResult struct {
	UserID   string
	Username string
	Token    string
}

// --- logging redaction ------------------------------------------------------
//
// Queries and responses are logged in full at debug level to make protocol
// debugging easy, but credentials must never reach the logs. These masks strip
// password arguments from outgoing documents (the pattern matches inside the
// input objects, e.g. `logIn(input: { ..., password: "..." })`) and
// token/secret values from responses while leaving the structure intact.

var (
	reRedactPassword = regexp.MustCompile(`(password\s*:\s*)"(?:[^"\\]|\\.)*"`)
	reRedactSecret   = regexp.MustCompile(`("(?:token|secret)"\s*:\s*)"(?:[^"\\]|\\.)*"`)
)

func redactQuery(query string) string {
	return reRedactPassword.ReplaceAllString(query, `${1}"***"`)
}

func redactResponse(body string) string {
	return reRedactSecret.ReplaceAllString(body, `${1}"***"`)
}

// --- GraphQL transport ------------------------------------------------------

// graphqlRequest is the GraphQL-over-HTTP POST body. Arguments are inlined into
// Query, so no variables object is sent.
type graphqlRequest struct {
	Query string `json:"query"`
}

// graphqlError is one entry in the top-level "errors" array.
type graphqlError struct {
	Message string `json:"message"`
}

// execute runs a single GraphQL operation against the endpoint and, when out is
// non-nil, unmarshals the "data" field into it. The server answers 200 even
// for resolver failures (graphql.Do encodes errors into the body), so the real
// signal is the top-level "errors" array; this surfaces transport errors,
// non-2xx status, and GraphQL errors alike so every caller fails loudly. The
// full request document and response body are logged at debug (with secrets
// masked).
//
// bearer, when non-empty, is sent as "Authorization: Bearer <token>".
func (c *graphqlClient) execute(ctx context.Context, opName, query, bearer string, out any) error {
	logger := c.log().With("operation", opName)

	body, err := json.Marshal(graphqlRequest{Query: query})
	if err != nil {
		return fmt.Errorf("encoding %s request: %w", opName, err)
	}

	logger.Debug("graphql request",
		"url", c.URL,
		"authenticated", bearer != "",
		"query", redactQuery(query),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building %s request: %w", opName, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		logger.Error("graphql transport error", "error", err)
		return fmt.Errorf("%s request to %s failed: %w", opName, c.URL, err)
	}
	defer resp.Body.Close()

	// Read the (capped) body once so it can be both logged and decoded, then
	// drain any remainder so the connection returns to the pool.
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_, _ = io.Copy(io.Discard, resp.Body)
	if readErr != nil {
		logger.Error("reading graphql response failed", "status", resp.StatusCode, "error", readErr)
		return fmt.Errorf("reading %s response: %w", opName, readErr)
	}

	logger.Debug("graphql response",
		"status", resp.StatusCode,
		"bytes", len(raw),
		"body", redactResponse(string(raw)),
	)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		logger.Error("graphql returned non-success status", "status", resp.StatusCode)
		return fmt.Errorf("%s failed: status %d: %s", opName, resp.StatusCode, strings.TrimSpace(redactResponse(string(raw))))
	}

	var envelope struct {
		Data   json.RawMessage `json:"data"`
		Errors []graphqlError  `json:"errors"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		logger.Error("decoding graphql response failed", "error", err)
		return fmt.Errorf("decoding %s response: %w", opName, err)
	}
	if len(envelope.Errors) > 0 {
		joined := joinGraphQLErrors(envelope.Errors)
		logger.Error("graphql operation returned errors", "errors", joined)
		return fmt.Errorf("%s returned errors: %s", opName, joined)
	}
	if out != nil {
		if err := json.Unmarshal(envelope.Data, out); err != nil {
			logger.Error("decoding graphql data failed", "error", err)
			return fmt.Errorf("decoding %s data: %w", opName, err)
		}
	}
	return nil
}

func joinGraphQLErrors(errs []graphqlError) string {
	msgs := make([]string, 0, len(errs))
	for _, e := range errs {
		msgs = append(msgs, e.Message)
	}
	return strings.Join(msgs, "; ")
}

// isCredentialGone reports whether err indicates the upstream credential (token
// or user) is already gone — an auth rejection or a missing resource. Lease
// revocation treats these as success so a credential the server has already
// dropped never wedges Vault's revocation queue into retrying forever. Genuine
// outages (connection errors, 5xx) are NOT matched, so Vault still retries.
//
// The server returns these as GraphQL errors over HTTP 200 (e.g.
// "unauthorized: missing or invalid token"), so the message markers matter
// more than the status markers, which are kept for proxies/gateways in front
// of the server.
func isCredentialGone(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, marker := range []string{
		"status 401", "status 403", "status 404",
		"unauthorized", "forbidden", "not found",
		"invalid token", "invalid credentials",
		"no such user", "does not exist", "unknown user",
	} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

// logIn authenticates username/password and returns the minted JWT. The
// server's AuthPayload carries only the token, never the user.
func (c *graphqlClient) logIn(ctx context.Context, username, password string) (string, error) {
	var data logInData
	if err := c.execute(ctx, "login", fmt.Sprintf(opSignin, gqlString(username), gqlString(password)), "", &data); err != nil {
		return "", err
	}
	if data.SignIn.Token == "" {
		return "", errors.New("login succeeded but returned an empty token")
	}
	return data.SignIn.Token, nil
}

// Me returns the identity behind the given token. ensureSession uses it to vet
// a stored session before reuse, and SignUp uses it as a fallback to resolve a
// new user's id; any failure during vetting just triggers a fresh sign-in.
func (c *graphqlClient) Me(ctx context.Context, token string) (identityPayload, error) {
	var data meData
	if err := c.execute(ctx, "me", opMe, token, &data); err != nil {
		return identityPayload{}, err
	}
	return data.Me, nil
}

// ensureSession returns a valid admin session token. It reuses the cached
// token when me confirms it still works; otherwise it signs in as the
// configured root user and caches the new token. refreshed is true only when a
// new token was minted, signaling the backend to persist it to config storage.
func (c *graphqlClient) ensureSession(ctx context.Context) (string, bool, error) {
	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()

	// Reuse a still-valid session. A me failure (expired token, deleted root
	// user) is not fatal: fall through and re-authenticate.
	if c.session != "" {
		if _, err := c.Me(ctx, c.session); err == nil {
			return c.session, false, nil
		}
		c.log().Debug("stored session not usable; re-authenticating")
	}

	token, err := c.logIn(ctx, c.Username, c.Password)
	if err != nil {
		return "", false, fmt.Errorf("admin login failed: %w", err)
	}
	c.session = token
	c.log().Info("established admin session")
	return c.session, true, nil
}

// SignUp provisions a dynamic USER and returns its credential (kept for
// user-mode issuance; role writes now mint service accounts via
// CreateServiceAccount). It creates the account, signs in as it, then
// verifies with me that the minted token actually belongs to the new user —
// a server login resolver minting for the wrong identity fails loudly here
// instead of leaking the wrong token into a lease.
func (c *graphqlClient) SignUp(ctx context.Context, session, username, password string) (*authResult, error) {
	var created createUserData
	if err := c.execute(ctx, "createUser", fmt.Sprintf(opSignup, gqlString(username), gqlString(password)), session, &created); err != nil {
		return nil, fmt.Errorf("creating user %q: %w", username, err)
	}

	token, err := c.logIn(ctx, username, password)
	if err != nil {
		return nil, fmt.Errorf("signing in new user %q: %w", username, err)
	}
	if session != "" && token == session {
		return nil, fmt.Errorf("login for %q returned the admin session token instead of a new credential; check the server's login resolver", username)
	}

	// me is authorized by the NEW token, so its answer is who the server
	// thinks this JWT belongs to.
	me, err := c.Me(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("verifying minted token for %q: %w", username, err)
	}
	if me.Username != username && me.Name != username {
		return nil, fmt.Errorf("minted token belongs to id=%q username=%q name=%q, expected %q; check the server's login resolver", me.ID, me.Username, me.Name, username)
	}

	userID := created.CreateUser.ID
	if userID == "" {
		userID = me.ID // me just ran; authoritative fallback
	}
	resolvedName := created.CreateUser.Username
	if resolvedName == "" {
		resolvedName = username
	}

	c.log().Info("provisioned dynamic user", "user_id", userID, "username", resolvedName)
	return &authResult{
		UserID:   userID,
		Username: resolvedName,
		Token:    token,
	}, nil
}

// DeleteUser destroys a dynamic user by USERNAME (the server's deleteUser is
// keyed by username, not id), authorized by the admin session. The mutation is
// idempotent upstream — deleting an absent user returns true — so retried
// lease revocations are safe. An empty username is a no-op. The server
// response is ignored (out == nil).
//
// NOTE: the server has no signout mutation and its JWTs are stateless with a
// 24h exp, so deleting the user is the strongest teardown available; an
// already-issued token only fully dies when it expires.
func (c *graphqlClient) DeleteUser(ctx context.Context, session, username string) error {
	if username == "" {
		c.log().Debug("no username to delete")
		return nil
	}
	if err := c.execute(ctx, "deleteUser", fmt.Sprintf(opDeleteUser, gqlString(username)), session, nil); err != nil {
		return fmt.Errorf("deleting user %q: %w", username, err)
	}
	c.log().Info("deleted dynamic user", "username", username)
	return nil
}

// CreateServiceAccount provisions a service account, authorized by the stored
// admin session bearer, and returns the token the server minted FOR IT at
// creation. Service accounts have no password and never touch login; the
// creation payload is the only place their token exists.
//
// Two guards keep a server bug from ever leasing out the root session:
//
//  1. The returned token must differ from the session bearer. A resolver that
//     echoes the caller's Authorization token (the exact "role write returns
//     the config token" failure) dies here instead of reaching a lease.
//  2. me, authorized by the NEW token, must report the identity as the
//     service account just created — catching a resolver that mints a valid
//     but wrong-identity token.

func (c *graphqlClient) CreateServiceAccount(ctx context.Context, session, name string) (*authResult, error) {
	var data createServiceAccountData
	if err := c.execute(ctx, "createServiceAccount", fmt.Sprintf(opCreateServiceAccount, gqlString(name)), session, &data); err != nil {
		return nil, fmt.Errorf("creating service account %q: %w", name, err)
	}

	payload := data.CreateServiceAccount
	if payload.Secret == "" {
		return nil, fmt.Errorf("createServiceAccount for %q returned no secret; the server must mint the credential in the creation payload", name)
	}
	if payload.Secret == session {
		return nil, fmt.Errorf("createServiceAccount for %q echoed the admin session token instead of minting a new credential; fix the server resolver to sign a JWT for the new service account", name)
	}

	me, err := c.Me(ctx, payload.Secret)
	if err != nil {
		return nil, fmt.Errorf("verifying minted secret for service account %q: %w", name, err)
	}
	if me.Name != name && me.Username != name {
		return nil, fmt.Errorf("minted secret belongs to id=%q username=%q name=%q, expected service account %q; the server is signing the JWT for the wrong identity", me.ID, me.Username, me.Name, name)
	}

	id := payload.ServiceAccount.ID
	if id == "" {
		id = me.ID // me just ran; authoritative fallback
	}
	resolvedName := payload.ServiceAccount.Name
	if resolvedName == "" {
		resolvedName = name
	}

	c.log().Info("provisioned service account", "id", id, "name", resolvedName)
	return &authResult{
		UserID:   id,
		Username: resolvedName,
		Token:    payload.Secret,
	}, nil
}

// DeleteServiceAccount destroys a service account by NAME, authorized by the
// admin session. An empty name is a no-op; the response is ignored. Lease
// revocation pairs this with isCredentialGone so an already-deleted account
// never wedges Vault's revocation queue.
func (c *graphqlClient) DeleteServiceAccount(ctx context.Context, session, name string) error {
	if name == "" {
		c.log().Debug("no service account name to delete")
		return nil
	}
	if err := c.execute(ctx, "deleteServiceAccount", fmt.Sprintf(opDeleteServiceAccount, gqlString(name)), session, nil); err != nil {
		return fmt.Errorf("deleting service account %q: %w", name, err)
	}
	c.log().Info("deleted service account", "name", name)
	return nil
}
