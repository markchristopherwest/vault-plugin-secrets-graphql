FROM --platform=$BUILDPLATFORM golang:1.26-trixie AS build

# Provided automatically by buildx for each --platform target.
ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

# Module-download layer: only re-runs when go.mod/go.sum change.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

# THE KEY LINE: CGO_ENABLED=0 produces a fully static binary with no libc
# dependency at all. The official Vault image is Alpine (musl libc); a binary
# dynamically linked against glibc would fail to exec there with a misleading
# "no such file or directory" (the file is present, its dynamic loader is not).
# A static binary sidesteps the whole musl-vs-glibc problem and runs on Alpine,
# distroless, or scratch — on any architecture.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o ./vault-plugin-secrets-graphql ./cmd/vault-plugin-secrets-graphql
# ^ point this at ./cmd/vault-plugin-secrets-graphql if main lives there

# ---- final stage: official Vault image, otherwise untouched ----
FROM hashicorp/vault:latest


# Switch briefly to root to manage file system permissions
USER root

# Alpine ships musl; gcompat provides the glibc runtime the plugin links against.
RUN apk add --no-cache gcompat libstdc++

# Create custom internal paths for your files
RUN mkdir -p /vault/plugins /vault/policies

COPY --from=build /src/vault-plugin-secrets-graphql /vault/plugins/graphql

# Explicitly add execute
RUN chmod +x /vault/plugins/graphql

# Explicitly grant ownership to the official Vault user/group (100:100)
RUN chown -R vault:1000 /vault/plugins /vault/policies

# Drop privileges back to the official built-in vault user
USER 1000
