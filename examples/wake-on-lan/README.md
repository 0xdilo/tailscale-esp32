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
git clone https://github.com/0xdilo/tailscale-esp32.git
cd tailscale-esp32/examples/wake-on-lan
cp .env.example .env
$EDITOR .env
./scripts/flash.sh
```

The flash helper prints the exact serial-monitor command for the detected port.
If the board is not `/dev/ttyACM0`, set it before flashing:

```bash
ESPFLASH_PORT=/dev/ttyUSB0 ./scripts/flash.sh
```

## First-time Tailscale enrollment

Flashing installs the firmware, but a new device must be approved once before
it belongs to a tailnet.

1. Start the serial monitor using the command printed by `flash.sh`. With the
   default port, it is:

   ```bash
   espflash monitor --port /dev/ttyACM0 \
     --elf target/xtensa-esp32s3-espidf/release/tailscale-esp32-wake
   ```

2. Wait for Wi-Fi and time synchronization. On a new identity, the log prints:

   ```text
   TAILSCALE APPROVAL REQUIRED: https://login.tailscale.com/a/...
   ```

3. Open that URL in a browser where you are signed into Tailscale. Confirm the
   tailnet and approve/connect the device. The URL is an enrollment link, not a
   credential that the firmware stores.

4. Return to the serial monitor. A successful enrollment eventually prints:

   ```text
   Tailscale control ready: addresses=100.x.y.z/32, peers=...
   ```

5. From another device connected to the same tailnet, verify discovery:

   ```bash
   tailscale status
   tailscale ping esp32-wake
   ```

   Replace `esp32-wake` with the `TAILSCALE_HOSTNAME` configured in `.env`.
   The node also appears in the Tailscale admin console's **Machines** page.

The generated private identity is persisted in ESP-IDF NVS. Normal firmware
updates reuse it, so approval happens only once. Erasing NVS, removing the node
from the admin console, or flashing identity-incompatible firmware requires a
new approval.

For unattended fleets, applications can use a short-lived, scoped Tailscale
auth key through `RegisterRequest::with_auth_key`. Provision it at install time;
never hardcode or commit it.

## Wake from a tailnet device

The easiest workflow is a normal ICMP ping:

```bash
ping esp32-wake
tailscale ping --icmp esp32-wake
```

On a phone, connect the official Tailscale app to the same tailnet and use an
ICMP ping utility with the configured hostname or the ESP's assigned `100.x`
address.

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
