#!/bin/sh
# Mint the dotvault-config service-account PKI from the dev Vault into
# dev/pki/: a dedicated CA, the mTLS listener's server certificate, and a
# short-lived client certificate for a service account.
#
# This is the same shape as production: a PKI secrets engine dedicated to
# dotvault-config service accounts (never a shared corporate CA — the
# service trusts this CA and nothing else, so the PKI role's issuance
# policy IS the admin-API access policy), with a role that
#   - pins the clientAuth EKU,
#   - allows only bare account names as the CN (no subdomains, no glob),
#   - caps TTL short (72h here; revocation = stop issuing + disable the
#     account in the admin API, no CRL distribution needed).
#
# Usage:
#   dev/mint-svc-cert.sh [account-name]   # default: terraform
#
# Requires the dev Vault from `docker compose up -d` and the vault CLI.
# Re-run any time; issuing is idempotent and certificates are just replaced.
set -eu

ACCOUNT="${1:-terraform}"
DIR="$(dirname "$0")/pki"
export VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
export VAULT_TOKEN="${VAULT_TOKEN:-dev-root-token}"

mkdir -p "$DIR"

# Dedicated mount for this trust domain.
vault secrets enable -path=dotvault-config-pki pki 2>/dev/null || true
vault secrets tune -max-lease-ttl=87600h dotvault-config-pki >/dev/null

# Root for the dev loop (production would use an intermediate under the
# organisation's offline root; the service only ever sees this CA's pem).
vault read -field=certificate dotvault-config-pki/cert/ca >"$DIR/ca.pem" 2>/dev/null ||
  vault write -field=certificate dotvault-config-pki/root/generate/internal \
    common_name="dotvault-config service accounts CA" ttl=87600h >"$DIR/ca.pem"

# Client role: CN = bare service-account name, clientAuth only, short TTL.
vault write dotvault-config-pki/roles/service-account \
  allow_any_name=false allow_bare_domains=true allow_subdomains=false \
  allow_glob_domains=false enforce_hostnames=false allowed_domains="$ACCOUNT" \
  client_flag=true server_flag=false key_type=ec key_bits=256 \
  max_ttl=72h ttl=24h >/dev/null

# Server role for the mTLS listener's own certificate.
vault write dotvault-config-pki/roles/listener \
  allow_any_name=false allow_bare_domains=true allow_subdomains=false \
  enforce_hostnames=false allowed_domains="localhost" \
  alt_names="localhost" client_flag=false server_flag=true \
  key_type=ec key_bits=256 max_ttl=720h ttl=720h >/dev/null

issue() {
  role="$1" cn="$2" prefix="$3"; shift 3
  out=$(vault write -format=json "dotvault-config-pki/issue/$role" common_name="$cn" "$@")
  printf '%s' "$out" | grep -o '"certificate": "[^"]*"' | head -1 | sed 's/.*: "//; s/"$//' | sed 's/\\n/\n/g' >"$DIR/$prefix.pem"
  printf '%s' "$out" | grep -o '"private_key": "[^"]*"' | head -1 | sed 's/.*: "//; s/"$//' | sed 's/\\n/\n/g' >"$DIR/$prefix-key.pem"
  chmod 600 "$DIR/$prefix-key.pem"
}

issue listener localhost server ip_sans="127.0.0.1"
issue service-account "$ACCOUNT" "$ACCOUNT"

cat <<EOF
Minted into $DIR:
  ca.pem                     pinned CA for admin.mtls.ca_cert
  server.pem / server-key.pem  mTLS listener certificate
  $ACCOUNT.pem / $ACCOUNT-key.pem  client certificate (CN=$ACCOUNT, 24h TTL)

Next:
  1. Uncomment the admin.mtls block in configsvc.dev.yaml and restart serve.
  2. Register the account (sign in to /admin/ or use the API):
       curl -sX PUT --cert $DIR/$ACCOUNT.pem --key $DIR/$ACCOUNT-key.pem \\
         --cacert $DIR/ca.pem https://127.0.0.1:9101/v1/admin/whoami
     (403 until a signed-in admin creates service account "$ACCOUNT").
EOF
