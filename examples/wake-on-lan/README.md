# Wake-on-LAN reference firmware

This ESP32-S3 application demonstrates how to build a single-purpose Tailscale
appliance with `tailscale-esp32`. It remains powered while a computer sleeps
and sends Wake-on-LAN after an authorized tailnet request.

The application supports two wake paths:

- an ACL-authorized ICMP echo through WireGuard, rate-limited to one wake burst
  every 30 seconds;
- a signed UDP request on tailnet port `41642`, protected by HMAC, timestamp,
  nonce, and replay checks.

The local signed HTTP endpoint is retained as a recovery fallback.

## Hardware assumptions

- ESP32-S3 with 8 MiB octal PSRAM and 16 MiB flash
- ESP-IDF 5.4.3 through Espressif's Rust toolchain
- a target computer whose firmware, Wi-Fi/Ethernet adapter, and operating
  system support Wake-on-LAN

Adjust `sdkconfig.defaults` and `.cargo/config.toml` for another ESP32 variant.

## Configure and flash

```bash
cp .env.example .env
$EDITOR .env
./scripts/flash.sh
```

On first boot, the device prints a Tailscale approval URL. Open it while logged
into the intended tailnet. The generated machine identity is persisted in NVS;
do not erase NVS unless you intend to register a new node.

## Wake from a tailnet device

The easiest workflow is a normal ICMP ping:

```bash
ping esp32-wake
tailscale ping --icmp esp32-wake
```

Tailscale's default DISCO ping is intentionally not a wake action because
clients send discovery probes automatically. Use ICMP explicitly.

For defense-in-depth application authentication:

```bash
./scripts/wake-tailscale.sh esp32-wake
```

## Current network limitation

The reference firmware maintains a direct UDP mapping and advertises it to the
control plane. DERP is not implemented, so remote access can fail when either
side blocks UDP or the home router uses an incompatible NAT. Keep a Raspberry
Pi or another full Tailscale node as a relay/fallback for unattended systems.
