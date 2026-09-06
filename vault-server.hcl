ui = true
disable_mlock = true

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

storage "raft" {
  path    = "/vault/data"
  node_id = "node1"
}

api_addr     = "http://127.0.0.1:8200"
cluster_addr = "http://127.0.0.1:8201"

# Second listener, TLS-enabled, for certificate auth.
#
# Vault's cert auth method rejects any login over a plain connection ("tls
# connection required"), so the HTTP listener above cannot exercise it at all.
# Rather than convert the whole dev stack to TLS — which would churn
# config.dev.yaml, the existing integration tests, and every documented curl —
# cert auth gets its own port and everything else carries on over 8200.
#
# The certificate is a throwaway self-signed cert generated into a volume at
# compose-up by the vault-tls service; it is never committed. Client certs are
# requested but not required, so ordinary HTTPS calls to this port still work.
listener "tcp" {
  address       = "0.0.0.0:8300"
  tls_cert_file = "/vault/tls/vault.crt"
  tls_key_file  = "/vault/tls/vault.key"
}
