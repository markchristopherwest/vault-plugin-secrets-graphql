# Full configuration options can be found at https://www.vaultproject.io/docs/configuration

ui = true
disable_mlock = true

storage "raft" {
  path = "/tmp"
  node_id = "docker"
}

listener "tcp" {
  address = "0.0.0.0:8200"
  tls_disable = true
}

listener "tcp" {
  address = "127.0.0.1:8201"
  tls_disable = true
}

api_addr = "http://127.0.0.1:8200"
cluster_addr = "http://127.0.0.1:8201"

// license_path = "/vault/lic/vault.hclic"

plugin_directory = "/vault/plugins"
