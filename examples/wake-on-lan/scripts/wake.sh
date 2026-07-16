#!/usr/bin/env bash

set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
env_file="$repo_dir/.env"
base_url="${1:-${ESP_WAKE_URL:-}}"

if [[ ! -f "$env_file" ]]; then
    printf 'Missing %s. Copy .env.example to .env and fill it in.\n' "$env_file" >&2
    exit 1
fi
if [[ -z "$base_url" ]]; then
    printf 'Usage: %s http://HOST[:PORT]\n' "$0" >&2
    exit 1
fi

set -a
source "$env_file"
set +a

: "${WAKE_TOKEN:?WAKE_TOKEN is required in .env}"
: "${WAKE_PATH:?WAKE_PATH is required in .env}"

timestamp="$(date +%s)"
nonce="$(openssl rand -hex 16)"
canonical="$(printf 'tailscale-esp32-wake-v1\n%s\n%s\nPOST\n%s' "$timestamp" "$nonce" "$WAKE_PATH")"
signature="$(
    printf '%s' "$canonical" \
        | openssl dgst -sha256 -hmac "$WAKE_TOKEN" -binary \
        | od -An -vtx1 \
        | tr -d ' \n'
)"

curl --fail --silent --show-error \
    --max-time 10 \
    --request POST \
    --header "X-Wake-Timestamp: $timestamp" \
    --header "X-Wake-Nonce: $nonce" \
    --header "X-Wake-Signature: $signature" \
    "${base_url%/}$WAKE_PATH"
