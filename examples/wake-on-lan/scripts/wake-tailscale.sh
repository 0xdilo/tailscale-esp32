#!/usr/bin/env bash

set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
env_file="$repo_dir/.env"
host="${1:-esp32-wake}"
port=41642

if [[ ! -f "$env_file" ]]; then
    printf 'Missing %s. Copy .env.example to .env and fill it in.\n' "$env_file" >&2
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

if command -v ncat >/dev/null 2>&1; then
    printf '%s\n%s\n%s\n' "$timestamp" "$nonce" "$signature" \
        | ncat --udp --send-only --idle-timeout 2s "$host" "$port"
else
    printf '%s\n%s\n%s\n' "$timestamp" "$nonce" "$signature" >"/dev/udp/$host/$port"
fi
printf 'Authenticated wake datagram sent to %s:%s over Tailscale.\n' "$host" "$port"
