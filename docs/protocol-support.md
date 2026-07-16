# Protocol support

The goal is a constrained Tailscale node for a narrow embedded application,
not a general-purpose userspace network stack.

| Area | Status | Notes |
| --- | --- | --- |
| Persistent identity | Implemented | Machine, node, DISCO, network-lock, and log identity |
| Control key retrieval | Application-provided | Reference app uses certificate-validated HTTPS |
| TS2021 Noise | Implemented | IK handshake, EarlyNoise, bounded records |
| Control HTTP/2 | Implemented | Minimal client required for registration and map requests |
| Registration | Implemented | Interactive follow-up and auth-key request support |
| Network maps | Implemented | Full, delta, resumable streaming, keepalive, and flow-control handling |
| Packet filters | Implemented | Default deny; source, destination, protocol, and port checks |
| WireGuard | Implemented | Responder/initiator, MAC1, TAI64N, counters, 128-packet replay window |
| DISCO | Implemented | Authenticated ping/pong, CallMeMaybe, and endpoint probing |
| STUN | Implemented | Tailscale software attribute and fingerprint |
| Direct UDP | Implemented | Depends on NAT behavior and peer reachability |
| DERP | Implemented | Authenticated v2 relay client; reference app accepts WireGuard over its home relay |
| Streaming maps | Implemented | HTTP/2 streaming, deltas, resume handles, and endpoint-triggered reconnects |
| Endpoint migration | Implemented | Authenticated probes, CallMeMaybe, direct-path expiry, and DERP fallback |
| Key rotation | Implemented | Transactional persistence, old-key registration, and tailnet-lock re-signing |
| IPv4 application packets | Implemented | Generic IP dispatch plus UDP and ICMP echo helpers |
| IPv6 application packets | Implemented | Generic dispatch, extension headers, UDP, and ICMPv6 echo helpers |
| TUN interface | Optional | Portable `PacketDevice` trait; direct dispatch remains cheaper on an ESP32 |
| Runtime adapters | Implemented | Abstract identity storage, clock, TCP, UDP, and packet-device boundaries |

## Security invariants

- Reject application traffic until a packet filter has been received.
- Bind an authenticated WireGuard peer key to the source address in AllowedIPs.
- Apply the received packet filter before dispatching a packet.
- Keep protocol and application parsers length-bounded.
- Persist the identity atomically and never log private key material.
- Add application authentication for high-impact actions, even inside a
  tailnet, when practical.

## Deliberate non-goals

This crate is still not a replacement for `tailscaled`. It does not provide a
general TCP/IP userspace stack, MagicDNS resolver, subnet or exit-node routing,
Tailscale SSH, Taildrop, serve/funnel, peer API, posture reporting, or the full
desktop configuration/state surface. The optional packet-device API is a
boundary for an application-provided TUN implementation, not a bundled OS VPN
driver.

Long-running release qualification should include power-loss rotation tests,
multi-day Wi-Fi outage recovery, changing NATs, and interoperability against
the Tailscale versions used by a deployment. The repository includes a live,
certificate-verified DERP smoke test, but it is opt-in because CI cannot assume
internet access or the `openssl` command.
