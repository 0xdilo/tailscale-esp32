# tailscale-esp32

Native Rust building blocks for running a small, purpose-built Tailscale node
on an ESP32. The protocol layer uses `std` but does not depend on ESP-IDF, so it
can be tested on a normal host and integrated with different embedded runtimes.

This is an independent implementation. It is not affiliated with or endorsed
by Tailscale Inc.

> [!IMPORTANT]
> The crate is usable for constrained applications, but it is not a drop-in
> replacement for `tailscaled`. Read the [support matrix](docs/protocol-support.md)
> before selecting it for a deployment.

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

The crate currently targets Rust 1.88 or newer. The reference firmware uses
Espressif's Rust toolchain and ESP-IDF 5.4.3.

## Security

This code handles long-lived network identities and unauthenticated UDP input.
Treat a device identity like a VPN private key, use encrypted storage when the
physical threat model requires it, and never commit `.env` files. Please report
security issues privately as described in [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
