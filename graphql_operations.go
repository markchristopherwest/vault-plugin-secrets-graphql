package secretsengine

// This file is the single place to edit the GraphQL the plugin speaks.
//
// The documents below match graphql-server-go@main exactly:
//
//	Mutation
//	  login(username: String!, password: String!) -> AuthPayload { token user { id } }  (open)
//	  createUser(input: CreateUserInput!)         -> User { id username }               (open)
//	  deleteUser(username: String!)               -> Boolean (idempotent)               [auth]
//	  createServiceAccount(name: String!)         -> { serviceAccount secret }          [auth]
//	  deleteServiceAccount(name: String!)         -> Boolean (idempotent)               [auth]
//	Query
//	  me -> Identity (User | ServiceAccount union)                                      [auth]
//
// Verified curl interface:
//
//	curl -X POST http://localhost:8080/graphql \
//	  -H "Content-Type: application/json" \
//	  -d '{"query":"mutation { login(username: \"admin\", password: \"changeme\") { token user { id } } }"}'
//
// The request payload is always {"query": "<document>"} — no variables, no
// operation names. String arguments are filled into the %s slots via
// gqlString (client.go), which JSON-escapes values so they can never break
// out of the document.
//
// Schema notes that shape the Go side (client.go):
//   - login takes BARE username/password arguments (no input object) and
//     its AuthPayload carries token plus an optional user { id }; the
//     client only decodes the token (logInData/authPayload) and resolves
//     identity via createUser or opMe.
//   - deleteUser is keyed by USERNAME, not id, and is idempotent: deleting
//     an absent user returns true, which keeps Vault lease revocation safe
//     to retry.
//   - me returns the Identity UNION, so the selection needs inline
//     fragments for each member type.
//   - The server has NO signout/logout mutation. Tokens are stateless JWTs
//     (24h exp), but the server re-resolves the JWT subject against live
//     storage on every request, so deleting the account kills its tokens
//     immediately — account deletion is the real teardown.

const (
	// opSignup creates a new account. Slots: username, password.
	// Open on the server, but the client still sends the admin session
	// bearer so nothing changes here if createUser is later gated.
	opSignup = `mutation { createUser(input: { username: %s, password: %s }) { id username } }`

	// opSignin authenticates an account and returns its JWT.
	// Slots: username, password. The user { id } selection is decoded
	// nowhere (authPayload carries only token) but is kept in the document
	// so the wire response is self-describing in debug logs.
	opSignin = `mutation { login(username: %s, password: %s) { token user { id } } }`

	// opMe returns the identity behind the token in the Authorization
	// header. Identity is a union, hence the inline fragments; both members
	// alias onto identityPayload in client.go. Used to vet the stored
	// config session token before reuse (see ensureSession) and as the
	// fallback source of a freshly provisioned user's id. No slots.
	opMe = `query { me { ... on User { id username } ... on ServiceAccount { id name } } }`

	// opDeleteUser destroys an account by USERNAME, invalidating the
	// record behind a leased credential. Idempotent upstream. The client
	// never decodes this payload (out == nil in DeleteUser). Slots: username.
	opDeleteUser = `mutation { deleteUser(username: %s) }`

	// --- service accounts ---------------------------------------------------
	//
	// Role writes and creds/<role> reads issue SERVICE ACCOUNTS, not users.
	// The server mints the service account's token AT CREATION and returns it
	// in the creation payload — service accounts have no password and never
	// go through login. The call is authorized by the stored config session
	// (admin) bearer; the token in the response is the NEW credential, which
	// must never equal that bearer (client.go enforces this; the server's
	// resolver signs the JWT for the new service account's id, so it can't).

	// If the live schema differs (bare name arg, token nested differently),
	// fix the document HERE and the matching decode struct
	// (createServiceAccountData in client.go); nothing else changes.

	// opCreateServiceAccount provisions a service account and returns its
	// freshly minted token plus identity. The credential lives under the
	// SECRET field of CreateServiceAccountPayload. Slots: name.
	opCreateServiceAccount = `mutation { createServiceAccount(name: %s ) { serviceAccount { id name } secret } }`

	// opDeleteServiceAccount destroys a service account by NAME. Idempotent
	// upstream like deleteUser so retried lease revocations stay safe;
	// isCredentialGone covers servers that error instead. The client never
	// decodes this payload. Slots: name.
	opDeleteServiceAccount = `mutation { deleteServiceAccount(name: %s) }`
)
