#!/usr/bin/env bash

set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
env_file="$repo_dir/.env"
port="${ESPFLASH_PORT:-/dev/ttyACM0}"

if [[ ! -f "$env_file" ]]; then
    printf 'Missing %s. Copy .env.example to .env and fill it in.\n' "$env_file" >&2
    exit 1
fi

set -a
source "$env_file"
set +a

: "${WIFI_SSID:?WIFI_SSID is required in .env}"
: "${WIFI_PASS:?WIFI_PASS is required in .env}"
: "${TAILSCALE_HOSTNAME:?TAILSCALE_HOSTNAME is required in .env}"
: "${WAKE_TOKEN:?WAKE_TOKEN is required in .env}"
: "${WAKE_PATH:?WAKE_PATH is required in .env}"
: "${WAKE_MAC:?WAKE_MAC is required in .env}"

cd "$repo_dir"
cargo build --release --features firmware
espflash flash --port "$port" target/xtensa-esp32s3-espidf/release/tailscale-esp32-wake

printf 'Flashed successfully. Start the serial log with:\n'
printf 'espflash monitor --port %q --elf target/xtensa-esp32s3-espidf/release/tailscale-esp32-wake\n' "$port"
