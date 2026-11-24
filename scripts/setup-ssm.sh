#!/usr/bin/env bash
# Creates the SSM parameters cogin and its first client need.
# Secrets are generated here and written straight to SSM; nothing secret is
# printed. Existing parameters are never overwritten: changing the signing key
# breaks issued tokens' verification for a while, and changing the PIN pepper
# silently invalidates every PIN that has been set.
#
#   ISSUER=https://auth.example.com \
#   CLIENT_ID=myapp CLIENT_NAME="My App" \
#   REDIRECT_URI=https://myapp.example.com/auth/card/callback \
#   INITIATE_LOGIN_URI=https://myapp.example.com/auth/card/start \
#   AWS_REGION=ap-northeast-1 ./scripts/setup-ssm.sh            # dry run
#   ... ./scripts/setup-ssm.sh --apply
#
# cogin's parameters go under $COGIN_PREFIX (default /cogin). The client's
# secret and admin key go under $CLIENT_PREFIX (default /$CLIENT_ID), for the
# client's own deployment to read.
set -euo pipefail

APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

: "${ISSUER:?set ISSUER, e.g. https://auth.example.com}"
: "${CLIENT_ID:?set CLIENT_ID, e.g. myapp}"
: "${CLIENT_NAME:=$CLIENT_ID}"
: "${REDIRECT_URI:?set REDIRECT_URI (the OIDC callback URL of the client)}"
: "${INITIATE_LOGIN_URI:=}"
: "${COGIN_PREFIX:=/cogin}"
: "${CLIENT_PREFIX:=/$CLIENT_ID}"
cd "$(dirname "$0")/.."

exists() { aws ssm get-parameter --name "$1" --query Parameter.Name --output text >/dev/null 2>&1; }

put() { # name type value
  if exists "$1"; then
    echo "keep   $1 (already exists)"
  elif $APPLY; then
    aws ssm put-parameter --name "$1" --type "$2" --value "$3" --no-overwrite >/dev/null
    echo "create $1 ($2)"
  else
    echo "would create $1 ($2)"
  fi
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
go build -o "$tmp/cogin" ./cmd/cogin

put "$COGIN_PREFIX/signing-key" SecureString "$("$tmp/cogin" gen-key)"
put "$COGIN_PREFIX/pin-pepper" SecureString "$("$tmp/cogin" gen-pepper)"

# The client: its secret and admin key go to the client's parameters, their
# hashes into cogin's config. Both sides are created together or not at all,
# otherwise the hashes would not match the secrets.
if exists "$COGIN_PREFIX/config" || exists "$CLIENT_PREFIX/cogin-client-secret" || exists "$CLIENT_PREFIX/cogin-admin-key"; then
  echo "keep   $COGIN_PREFIX/config, $CLIENT_PREFIX/cogin-client-secret, $CLIENT_PREFIX/cogin-admin-key (at least one exists; not regenerating)"
else
  "$tmp/cogin" new-client "$CLIENT_ID" > "$tmp/client.txt"
  secret=$(awk '/^client_secret/ {print $3}' "$tmp/client.txt")
  admin=$(awk '/^admin_key/ {print $3}' "$tmp/client.txt")
  secret_hash=$(sed -nE 's/^"secretHash": "([0-9a-f]+)",?$/\1/p' "$tmp/client.txt")
  admin_hash=$(sed -nE 's/^"adminKeyHash": "([0-9a-f]+)",?$/\1/p' "$tmp/client.txt")
  if [[ -z "$secret" || -z "$admin" || -z "$secret_hash" || -z "$admin_hash" ]]; then
    echo "failed to parse new-client output" >&2
    exit 1
  fi
  # The filter is kept in a variable: bash 3.2 (macOS) misparses parentheses
  # inside a quoted string in $(...).
  filter='{issuer: $issuer, clients: [{id: $id, name: $name, redirectUris: [$redirect],
    secretHash: $sh, adminKeyHash: $ah} + (if $initiate == "" then {} else {initiateLoginUri: $initiate} end)]}'
  config=$(jq -cn \
    --arg issuer "$ISSUER" --arg id "$CLIENT_ID" --arg name "$CLIENT_NAME" \
    --arg redirect "$REDIRECT_URI" --arg initiate "$INITIATE_LOGIN_URI" \
    --arg sh "$secret_hash" --arg ah "$admin_hash" "$filter")
  put "$COGIN_PREFIX/config" String "$config"
  put "$CLIENT_PREFIX/cogin-client-secret" SecureString "$secret"
  put "$CLIENT_PREFIX/cogin-admin-key" SecureString "$admin"
fi

$APPLY || echo "(dry run: re-run with --apply to create)"
