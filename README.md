# GraphQL Secrets Engine — Credential Management Lifecycle

End-to-end flow against Vault's HTTP API, from bringing up the GraphQL server
to issuing, renewing, rotating, revoking, and tearing down credentials. Every
step gives the full **Vault API** `curl` (JSON bodies via heredoc, in the same
style as `do_setup_graphql` / `do_setup_vault` in `run`), the **Vault CLI**
equivalent, and — where the engine calls upstream — the **GraphQL API** request
it issues. Concrete values (mount `gql`, plugin/catalog name `graphql`,
version `v1.0.0`, URL `http://graphql:8080/graphql`) match the `run` script.

**Issuance model.** `POST role/<name>` persists the role definition *and* mints
the first leased credential in the same call. `GET role/<name>` returns the role
definition only. `GET creds/<name>` is the generate action: every read logs the
engine in as the configured root user (session cached in config storage), calls
`createServiceAccount(name)` upstream, records the result under
`token/<token_id>`, and returns the server-minted secret as a *leased* Vault
secret. It is **not idempotent** — every read is a new service account and a new
lease. Revoking the lease deletes the upstream service account. `user_id` is a
string (`"sa_..."` / `"usr_..."`).

### A note on `| jq` and heredocs

In every heredoc call the `| jq` sits on the **same line as the `<<EOF`
redirect**, i.e. *before* the JSON body and *outside* the `EOF ... EOF` block,
so it pipes curl's stdout (not the request body) into jq:

```bash
curl ... --data @- "URL" <<EOF | jq      # <-- jq is here, outside the body
{ "json": "body" }
EOF
```

- Bodies that interpolate a shell variable use unquoted `<<EOF`.
- Literal GraphQL bodies (which contain `\"`) use quoted `<<'EOF'` so nothing
  is expanded.
- Operations that return **204 No Content** (most `DELETE`s, lease revoke,
  revoke-prefix, and config write) have no JSON body, so piping them to `jq`
  fails. Those print the HTTP status with `-w '%{http_code}\n' -o /dev/null`
  instead of `| jq`.

## 0. Environment

```bash
export VAULT_ADDR="http://127.0.0.1:8200"

# run pulls the root token out of the unseal file; substitute your own token if different:
export VAULT_TOKEN="$(cat ./sensitive/vault/vault.txt | grep '^Initial' | awk '{print $4}')"

export MOUNT="gql"                                # engine mount path (from run)
export PLUGIN="graphql"                           # catalog name == mount type == command (binary filename)
export PLUGIN_VERSION="v1.0.0"                    # registered plugin version (from run)
export ROLE="admin"                               # example role name; any name works
export GRAPHQL_URL="http://graphql:8080/graphql"  # vault container -> graphql container (compose network)
                                                  # use http://localhost:8080/graphql for host -> graphql
```

Every Vault request authenticates with the `X-Vault-Token` header; all engine
paths live under `/v1/${MOUNT}/...`.

## 1. Bring up and verify the GraphQL server

```bash
docker compose up -d        # brings up graphql + vault (as in run's do_compose)
```

Seed the initial users and confirm login directly against the server — this is
the exact `login` the engine performs internally before issuing credentials.

**GraphQL API — create users:**

```bash
curl -sS -X POST \
  -H "Content-Type: application/json" \
  --data @- \
  "http://localhost:8080/graphql" <<'EOF' | jq
{"query": "mutation { createUser(username: \"admin\", password: \"changeme\") { id username } }"}
EOF
```

```bash
curl -sS -X POST \
  -H "Content-Type: application/json" \
  --data @- \
  "http://localhost:8080/graphql" <<'EOF' | jq
{"query": "mutation { createUser(username: \"jane_doe\", password: \"secret123\") { id username } }"}
EOF
```

**GraphQL API — login (capture the admin token):**

```bash
export TOKEN_ADMIN="$(curl -sS -X POST \
  -H "Content-Type: application/json" \
  --data @- \
  "http://localhost:8080/graphql" <<'EOF' | jq -r '.data.login.token'
{"query": "mutation { login(username: \"admin\", password: \"changeme\") { token user { id } } }"}
EOF
)"
echo "admin token: ${TOKEN_ADMIN}"
```

A non-empty `data.login.token` means the upstream is ready.

**GraphQL API — mint a service account as admin (the operation the engine wraps):**

```bash
curl -sS -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN_ADMIN}" \
  --data @- \
  "http://localhost:8080/graphql" <<'EOF' | jq
{"query": "mutation { createServiceAccount(name: \"Background Job\") { serviceAccount { id name } secret } }"}
EOF
```

> Service accounts cannot create other service accounts: repeating the
> `createServiceAccount` mutation with `Authorization: Bearer <service-account secret>`
> returns a `forbidden` error. Only real users (e.g. `admin`) may mint them —
> which is why the engine authenticates as the configured root user.

## 2. Register and mount the plugin

Copy the binary out of the Vault container and checksum it, exactly as `run`
does. The `sha256` must match the binary in Vault's `plugin_directory`;
`command` is its filename there.

```bash
docker cp vault:/vault/plugins/${PLUGIN} ./plugins/vault/${PLUGIN}
if [[ "$OSTYPE" == "darwin"* ]]; then
  export SHA256="$(shasum -a 256 ./plugins/vault/${PLUGIN} | cut -d ' ' -f1)"
else
  export SHA256="$(sha256sum ./plugins/vault/${PLUGIN} | cut -d ' ' -f1)"
fi
echo "${SHA256}"
```

**Vault API — register in the catalog** (204 No Content on success):

```bash
curl -sS -X POST \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  -H "Content-Type: application/json" \
  --data @- \
  -w '%{http_code}\n' -o /dev/null \
  "${VAULT_ADDR}/v1/sys/plugins/catalog/secret/${PLUGIN}" <<EOF
{
  "sha256": "${SHA256}",
  "command": "${PLUGIN}",
  "args": [],
  "version": "${PLUGIN_VERSION}"
}
EOF
```

Read the catalog entry back:

```bash
curl -sS \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  "${VAULT_ADDR}/v1/sys/plugins/catalog/secret/${PLUGIN}?version=${PLUGIN_VERSION}" | jq
```

**Vault API — enable (mount) the engine at `gql`** (204 No Content):

```bash
curl -sS -X POST \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  -H "Content-Type: application/json" \
  --data @- \
  -w '%{http_code}\n' -o /dev/null \
  "${VAULT_ADDR}/v1/sys/mounts/${MOUNT}" <<EOF
{
  "type": "${PLUGIN}"
}
EOF
```

**Vault CLI:**

```bash
vault plugin register -sha256="${SHA256}" -command="${PLUGIN}" -version="${PLUGIN_VERSION}" secret "${PLUGIN}"
vault secrets enable -path="${MOUNT}" "${PLUGIN}"
```

**GraphQL API:** none — registration and mounting are Vault-only.

## 3. Configure the engine

Point the engine at the GraphQL server and give it the root user it
authenticates as. `username`, `password`, and `url` are required on create.
Writing config clears any stored session token, so the next request logs in
fresh.

**Vault API — write config (204 No Content on success):**

```bash
curl -sS -X POST \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  -H "Content-Type: application/json" \
  --data @- \
  -w '%{http_code}\n' -o /dev/null \
  "${VAULT_ADDR}/v1/${MOUNT}/config" <<EOF
{
  "url": "${GRAPHQL_URL}",
  "username": "admin",
  "password": "changeme"
}
EOF
```

**Vault API — read config back** (`password` and the cached session `token`
are never returned; `has_session_token` reports whether a session is stored):

```bash
curl -sS \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  "${VAULT_ADDR}/v1/${MOUNT}/config" | jq
```

**Vault CLI:**

```bash
vault write "${MOUNT}/config" url="${GRAPHQL_URL}" username=admin password=changeme
vault read  "${MOUNT}/config"
```

**GraphQL API:** none at write time. On the next credential issuance the engine
authenticates with the stored root credentials via:

```graphql
mutation { login(username: "admin", password: "changeme") { token user { id } } }
```

## 4. Create a role (mints the first leased credential)

A role pins the upstream `username` that issued service-account names are
attributed to (`vault-<username>-<short id>`), plus the lease TTLs. `username`
is required on create; `ttl`/`max_ttl` accept Go durations (`"1h"`) or integer
seconds. **The write response is itself a leased credential** — same issuance
path as `creds/`.

**Vault API — create role (returns a leased credential):**

```bash
curl -sS -X POST \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  -H "Content-Type: application/json" \
  --data @- \
  "${VAULT_ADDR}/v1/${MOUNT}/role/${ROLE}" <<EOF | jq
{
  "username": "admin",
  "ttl": "1h",
  "max_ttl": "24h"
}
EOF
```

**Vault API — read the definition back** (no credential is minted by a read):

```bash
curl -sS \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  "${VAULT_ADDR}/v1/${MOUNT}/role/${ROLE}" | jq
```

**Vault API — list role names** (both forms work):

```bash
curl -sS -X LIST \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  "${VAULT_ADDR}/v1/${MOUNT}/role" | jq
```

```bash
curl -sS \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  "${VAULT_ADDR}/v1/${MOUNT}/role?list=true" | jq
```

**Vault CLI:**

```bash
vault write "${MOUNT}/role/${ROLE}" username=admin ttl=1h max_ttl=24h   # returns a leased credential
vault read  "${MOUNT}/role/${ROLE}"                                     # role definition only
vault list  "${MOUNT}/role"
```

**GraphQL API:** the engine logs in (if no cached session) and mints the first
credential:

```graphql
mutation { createServiceAccount(name: "vault-admin-<short id>") { serviceAccount { id name } secret } }
```

## 5. Issue a credential (`creds/<role>`)

Each read provisions a brand-new service account and returns its server-minted
token under a fresh lease. Capture `lease_id` and `token_id` for the
renew/rotate/revoke steps.

**Vault API:**

```bash
CREDS_JSON="$(curl -sS \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  "${VAULT_ADDR}/v1/${MOUNT}/creds/${ROLE}")"
echo "${CREDS_JSON}" | jq
export LEASE_ID="$(echo "${CREDS_JSON}" | jq -r '.lease_id')"
export TOKEN_ID="$(echo "${CREDS_JSON}" | jq -r '.data.token_id')"
```

Response shape:

```json
{
  "lease_id": "gql/creds/admin/2f5d8c1a...",
  "lease_duration": 3600,
  "renewable": true,
  "data": {
    "token": "<service-account secret — the credential>",
    "token_id": "0b2e6c0e-...",
    "user_id": "sa_42",
    "username": "vault-admin-0b2e6c0e",
    "role": "admin"
  }
}
```

`data.token` is what your client presents as `Authorization: Bearer <token>`.
When the lease expires or is revoked, the engine destroys that service account
upstream.

**Vault CLI:**

```bash
vault read "${MOUNT}/creds/${ROLE}"
```

**GraphQL API:** identical to step 4's issuance — login (if the cached session
expired) then:

```graphql
mutation { createServiceAccount(name: "vault-admin-<short id>") { serviceAccount { id name } secret } }
```

## 6. Inspect token records (`token/<token_id>`)

Every minted credential is recorded under `token/<token_id>` (seal-wrapped).
Reads return metadata only — the raw token was returned exactly once at issue
time and is never re-served.

**Vault API:**

```bash
curl -sS -X LIST \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  "${VAULT_ADDR}/v1/${MOUNT}/token" | jq
```

```bash
curl -sS \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  "${VAULT_ADDR}/v1/${MOUNT}/token/${TOKEN_ID}" | jq
```

Deleting a record removes **bookkeeping only** — it does not revoke the upstream
account; that belongs to the lease lifecycle (step 9). Returns 204:

```bash
curl -sS -X DELETE \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  -w '%{http_code}\n' -o /dev/null \
  "${VAULT_ADDR}/v1/${MOUNT}/token/${TOKEN_ID}"
```

**Vault CLI:**

```bash
vault list   "${MOUNT}/token"
vault read   "${MOUNT}/token/${TOKEN_ID}"
vault delete "${MOUNT}/token/${TOKEN_ID}"
```

**GraphQL API:** none — these are Vault storage records, not upstream calls.

## 7. Renew the lease

Renewal extends the lease using the role's `ttl`, bounded by `max_ttl`.

**Vault API:**

```bash
curl -sS -X PUT \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  -H "Content-Type: application/json" \
  --data @- \
  "${VAULT_ADDR}/v1/sys/leases/renew" <<EOF | jq
{
  "lease_id": "${LEASE_ID}",
  "increment": 600
}
EOF
```

**Vault CLI:**

```bash
vault lease renew -increment=600 "${LEASE_ID}"
```

**GraphQL API:** none — renewal only extends the Vault lease TTL; the upstream
service account is untouched.

## 8. Rotate a credential

The engine has no standalone rotate endpoint; rotation is the lease-native
two-step: **mint a replacement, then revoke the old lease.** The old credential
keeps working during the cutover window, so consumers swap tokens without
downtime.

**Vault API — mint the replacement and capture its identifiers:**

```bash
OLD_LEASE_ID="${LEASE_ID}"

CREDS_JSON="$(curl -sS \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  "${VAULT_ADDR}/v1/${MOUNT}/creds/${ROLE}")"
echo "${CREDS_JSON}" | jq
export LEASE_ID="$(echo "${CREDS_JSON}" | jq -r '.lease_id')"
export TOKEN_ID="$(echo "${CREDS_JSON}" | jq -r '.data.token_id')"
```

**Vault API — once consumers hold the new token, revoke the old lease** (204;
this deletes the old service account upstream and drops its `token/` record):

```bash
curl -sS -X PUT \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  -H "Content-Type: application/json" \
  --data @- \
  -w '%{http_code}\n' -o /dev/null \
  "${VAULT_ADDR}/v1/sys/leases/revoke" <<EOF
{
  "lease_id": "${OLD_LEASE_ID}"
}
EOF
```

**Vault CLI:**

```bash
vault read "${MOUNT}/creds/${ROLE}"      # mint replacement
vault lease revoke "${OLD_LEASE_ID}"     # retire the old credential
```

**GraphQL API:** mint uses `createServiceAccount` (step 4); retiring the old
lease issues the engine's delete-service-account mutation against the old
account's id (see step 9).

> The server's JWTs are stateless (24h exp) with **no signout mutation**, but it
> re-resolves the JWT subject against live storage on every request — so deleting
> the account kills its tokens immediately. Account deletion via lease revocation
> is the real teardown.

## 9. Revoke a credential (deletion)

Revoke immediately by lease — destroys the upstream service account and removes
the stored `token/` record. Revocation is hardened: if the account is already
gone upstream (401/403/not-found), the revoke still completes instead of wedging
Vault's revocation queue.

**Vault API — revoke one lease (204):**

```bash
curl -sS -X PUT \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  -H "Content-Type: application/json" \
  --data @- \
  -w '%{http_code}\n' -o /dev/null \
  "${VAULT_ADDR}/v1/sys/leases/revoke" <<EOF
{
  "lease_id": "${LEASE_ID}"
}
EOF
```

**Vault API — revoke everything this mount has ever leased** (prefix revoke, 204):

```bash
curl -sS -X PUT \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  -w '%{http_code}\n' -o /dev/null \
  "${VAULT_ADDR}/v1/sys/leases/revoke-prefix/${MOUNT}"
```

**Vault CLI:**

```bash
vault lease revoke "${LEASE_ID}"
vault lease revoke -prefix "${MOUNT}/"
```

**GraphQL API:** the engine destroys the upstream account using the stored
service-account id. The mutation is issued internally — confirm the exact field
and argument names against the engine's `client.go`; it mirrors:

```graphql
mutation { deleteServiceAccount(id: "<service-account id>") { id } }
```

## 10. Tear down the role, config, and mount

**Vault API — delete the role** (204; does not revoke already-issued leases):

```bash
curl -sS -X DELETE \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  -w '%{http_code}\n' -o /dev/null \
  "${VAULT_ADDR}/v1/${MOUNT}/role/${ROLE}"
```

**Vault API — delete the config** (204):

```bash
curl -sS -X DELETE \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  -w '%{http_code}\n' -o /dev/null \
  "${VAULT_ADDR}/v1/${MOUNT}/config"
```

**Vault API — unmount the engine** (204; revokes all of the mount's outstanding
leases as part of unmount):

```bash
curl -sS -X DELETE \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  -w '%{http_code}\n' -o /dev/null \
  "${VAULT_ADDR}/v1/sys/mounts/${MOUNT}"
```

**Vault CLI:**

```bash
vault delete "${MOUNT}/role/${ROLE}"
vault delete "${MOUNT}/config"
vault secrets disable "${MOUNT}"
```

**GraphQL API:** deleting the role or config makes no upstream call. Unmounting
revokes outstanding leases, and each revocation issues the delete-service-account
mutation from step 9 for its account.

> Deleting a role does not revoke leases already issued from it — revoke them
> first (step 9) or let them expire; unmounting revokes all of the mount's
> outstanding leases as part of unmount.

## Appendix A — Full lifecycle, Vault CLI only

```bash
vault plugin register -sha256="${SHA256}" -command="${PLUGIN}" -version="${PLUGIN_VERSION}" secret "${PLUGIN}"
vault secrets enable -path="${MOUNT}" "${PLUGIN}"
vault write  "${MOUNT}/config" url="${GRAPHQL_URL}" username=admin password=changeme
vault read   "${MOUNT}/config"
vault write  "${MOUNT}/role/${ROLE}" username=admin ttl=1h max_ttl=24h   # persists role + returns leased credential
vault read   "${MOUNT}/role/${ROLE}"        # role definition
vault list   "${MOUNT}/role"
vault read   "${MOUNT}/creds/${ROLE}"       # mint a credential (new lease every read)
vault list   "${MOUNT}/token"               # issued-credential records
vault read   "${MOUNT}/token/<token_id>"    # record metadata (never the raw token)
vault lease renew -increment=600 <lease_id>
vault read   "${MOUNT}/creds/${ROLE}"       # rotate: mint replacement...
vault lease revoke <old_lease_id>           # ...then retire the old one
vault lease revoke <lease_id>               # revoke = upstream account deleted
vault lease revoke -prefix "${MOUNT}/"
vault delete "${MOUNT}/role/${ROLE}"
vault delete "${MOUNT}/config"
vault secrets disable "${MOUNT}"
```

## Appendix B — GraphQL operations reference

All requests go to `POST ${GRAPHQL_URL}` (or `http://localhost:8080/graphql`
from the host) with `Content-Type: application/json`. Service-account mutations
require `Authorization: Bearer <user token>`.

| Operation | When the engine uses it | Mutation |
| --- | --- | --- |
| `createUser` | seeding only (not engine-driven) | `mutation { createUser(username: "...", password: "...") { id username } }` |
| `login` | before any issuance, using config root creds | `mutation { login(username: "...", password: "...") { token user { id } } }` |
| `createServiceAccount` | `POST role/<name>` and `GET creds/<name>` | `mutation { createServiceAccount(name: "...") { serviceAccount { id name } secret } }` |
| `deleteServiceAccount` | lease revoke / rotate / unmount (internal) | `mutation { deleteServiceAccount(id: "...") { id } }` *(confirm exact name in `client.go`)* |

## Reconciliation notes (vs the previous README)

These are the mismatches between the old README and `run` that were corrected:

- **Mount path** `graphql` → **`gql`** (`run` mounts at `/v1/sys/mounts/gql` and
  uses `/v1/gql/...`).
- **Catalog / plugin name** `vault-plugin-secrets-graphql` → **`graphql`**, with
  **`command: graphql`**, **`args: []`** and **`version: v1.0.0`** in the
  registration body, and `?version=v1.0.0` on catalog reads.
- **Config URL** is **`http://graphql:8080/graphql`** (compose network), and the
  config body order matches `run`: `url`, `username`, `password`.
- **Role / creds paths** use the **path form** `role/<name>` and `creds/<name>`
  (the form `do_login` actually calls), not the `?name=` query form that appears
  in the exploratory parts of `do_setup_vault`.
- **Lease TTLs** are `ttl=1h` / `max_ttl=24h`, matching `run`'s role body.
- **`| jq` placement** is fixed to sit outside the heredoc body on the `<<EOF`
  line, and **204 No Content** operations print `%{http_code}` instead of being
  piped to `jq` (where jq would otherwise fail on an empty body).
- Added the **GraphQL API** request alongside the Vault API + CLI for every step.
