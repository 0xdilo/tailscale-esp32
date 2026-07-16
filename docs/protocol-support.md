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
| Network maps | Implemented | Full and delta decoding; reference app polls periodically |
| Packet filters | Implemented | Default deny; source, destination, protocol, and port checks |
| WireGuard | Implemented | Responder/initiator, MAC1, TAI64N, counters, 128-packet replay window |
| DISCO | Partial | Authenticated ping/pong |
| STUN | Implemented | Tailscale software attribute and fingerprint |
| Direct UDP | Implemented | Depends on NAT behavior and peer reachability |
| DERP | Not implemented | No relay fallback on blocked UDP or symmetric NAT |
| Streaming maps | Not implemented | Polling nodes may appear offline in the admin console |
| Endpoint migration | Partial | Reference app refreshes a stable public mapping |
| Key rotation | Not implemented | Re-enrollment is currently required |
| IPv4 application packets | Partial | UDP and ICMP echo parsing in the current API |
| IPv6 application packets | Partial | UDP parsing only |
| TUN interface | Out of scope | Applications dispatch packets directly |

## Security invariants

- Reject application traffic until a packet filter has been received.
- Bind an authenticated WireGuard peer key to the source address in AllowedIPs.
- Apply the received packet filter before dispatching a packet.
- Keep protocol and application parsers length-bounded.
- Persist the identity atomically and never log private key material.
- Add application authentication for high-impact actions, even inside a
  tailnet, when practical.

## Roadmap

1. Streaming network-map sessions and clean reconnect/resume behavior.
2. DERP framing and authenticated relay sessions.
3. CallMeMaybe, endpoint migration, and symmetric-NAT traversal.
4. Node key rotation and long-duration outage recovery.
5. A higher-level runner API over abstract storage, clock, TCP, and UDP traits.
6. Endurance and interop testing against multiple Tailscale client versions.
