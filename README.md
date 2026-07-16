# tailscale-esp32

```text
       /\_/\\
      ( o.o )   tailnet ready~
       > ^ <
```

Native Rust building blocks for running a small, purpose-built Tailscale node
on an ESP32. The protocol layer uses `std` but does not depend on ESP-IDF, so it
can be tested on a normal host and integrated with different embedded runtimes.

This is an independent implementation. It is not affiliated with or endorsed
by Tailscale Inc.

> [!IMPORTANT]
> The crate is usable for constrained applications, but it is not a drop-in
> replacement for `tailscaled`. Read the [support matrix](docs/protocol-support.md)
> before selecting it for a deployment.

The ESP32-S3 reference build is tuned for constrained always-on appliances.
See the measured [footprint, memory, and idle-power optimizations](docs/optimization.md).

## What is implemented

- Tailscale machine, node, discovery, challenge, and network-lock key types
- versioned persistent device identities with zeroized private key storage
- TS2021 Noise IK control-plane upgrade and EarlyNoise
- bounded HTTP/2 framing and HPACK
- interactive or auth-key registration and network-map decoding
- default-deny packet-filter evaluation
- WireGuard IKpsk2 handshakes, transport encryption, and anti-replay window
- authenticated DISCO ping/pong
- Tailscale-compatible STUN discovery
- IPv4 UDP parsing and ICMP echo replies for small application data planes

All parsers have explicit size limits. Private keys do not implement `Debug`,
and key material is zeroized when dropped.

## Crate layout

The modules intentionally map to protocol boundaries:

- `identity` and `key`: persistent node identity
- `client`, `noise`, `h2`, and `control`: coordination server transport
- `wireguard`: encrypted peer sessions
- `disco` and `stun`: direct-path discovery
- `netmap`: peers, AllowedIPs, and ACL checks

Applications supply sockets, persistent storage, scheduling, and packet
dispatch. This keeps policy and hardware choices outside the protocol crate.

## How a new ESP32 joins a tailnet

The crate does not contain a Tailscale account password or reusable auth key.
An application creates a device identity, stores it in NVS, and sends its
public keys to the Tailscale control plane. For interactive enrollment:

1. The ESP32 generates machine, node, DISCO, and network-lock keys on first
   boot and persists the private keys locally.
2. The registration response contains a one-time approval URL.
3. The firmware prints that URL to its serial log.
4. A user who is already signed into Tailscale opens the URL and approves the
   device for the intended tailnet.
5. Tailscale assigns the node a `100.x.y.z` address and MagicDNS name.
6. Later boots authenticate with the persisted device keys; the approval step
   does not repeat unless NVS is erased or the node is removed.

The [Wake-on-LAN onboarding guide](examples/wake-on-lan/README.md#first-time-tailscale-enrollment)
shows the complete terminal and browser workflow. Applications may instead
call `RegisterRequest::with_auth_key` for unattended provisioning, but the auth
key must be supplied securely and must never be compiled into firmware.

## Minimal identity setup

```rust
use tailscale_esp32::control::HostInfo;
use tailscale_esp32::identity::DeviceIdentity;

let identity = DeviceIdentity::generate()?;
let persistent_bytes = identity.encode();

// Persist `persistent_bytes` in NVS and restore it on the next boot.
let restored = DeviceIdentity::decode(&persistent_bytes)?;
let host = HostInfo::esp32("sensor-node", "0123456789abcdef");

assert_eq!(
    identity.machine_key().public(),
    restored.machine_key().public()
);
# Ok::<(), Box<dyn std::error::Error>>(())
```

See [`examples/wake-on-lan`](examples/wake-on-lan) for a complete ESP-IDF
application that registers a node, maintains direct connectivity, enforces the
tailnet packet filter, and dispatches authenticated application packets.

## Development

Host-side validation:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo test --manifest-path examples/wake-on-lan/Cargo.toml \
  --target x86_64-unknown-linux-gnu
```

ESP32-S3 build validation:

```bash
cd examples/wake-on-lan
cp .env.example .env
# Fill in local values, then:
./scripts/flash.sh
```

Flashing the example is not the final enrollment step. Follow the approval URL
in the serial monitor as described in the example's onboarding guide.

The crate currently targets Rust 1.88 or newer. The reference firmware uses
Espressif's Rust toolchain and ESP-IDF 5.4.3.

## Security

This code handles long-lived network identities and unauthenticated UDP input.
Treat a device identity like a VPN private key, use encrypted storage when the
physical threat model requires it, and never commit `.env` files. Please report
security issues privately as described in [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
