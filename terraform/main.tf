terraform {
  required_providers {
    vault = {
      source = "hashicorp/vault"
      version = "3.24.0"
    }
  }
}

provider "vault" {
  # Configuration options
  # address = "http://127.0.0.1:8200"
  # skip_tls_verify = true
}

data "vault_policy_document" "graphql" {
  rule {
    path         = "gql/*"
    capabilities = ["create", "read", "update", "delete", "list"]
    description  = "Work with graphql secrets engine"
  }
  rule {
    path         = "sys/mounts/*"
    capabilities = ["create", "read", "update", "delete", "list"]
    description  = "Enable secrets engine"
  }
  rule {
    path         = "sys/mounts"
    capabilities = [ "read", "list"]
    description  = "List enabled secrets engine"
  }
}

resource "vault_policy" "graphql" {
  name   = "graphql_policy"
  policy = data.vault_policy_document.graphql.hcl
}


