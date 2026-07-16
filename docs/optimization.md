# Embedded optimization notes

The reference firmware is tuned for a low-traffic, always-on ESP32-S3 node.
The choices below favor bounded memory, low idle activity, and small flash over
bulk VPN throughput.

## Measured footprint

Measurements are from the Wake-on-LAN example linked for an ESP32-S3 with
ESP-IDF 5.4.3. The comparison uses the same application and dependency set.

| Metric | Initial release build | Optimized build | Change |
| --- | ---: | ---: | ---: |
| Flashable application image | 1,614,832 B | 1,381,184 B | -233,648 B (-14.5%) |
| `.flash.text` | 1,363,700 B | 980,364 B | -383,336 B (-28.1%) |
| `.flash.rodata` | 380,380 B | 279,428 B | -100,952 B (-26.5%) |
| Explicit application task stacks | 98 KiB | 78 KiB | -20 KiB (-20.4%) |

The completed relay/streaming runtime build measures 1,440,208 B as a
flashable image (`.flash.text` 1,032,636 B and `.flash.rodata` 286,172 B).
That is 59,024 B larger than the direct-only optimized build while remaining
174,624 B smaller than the initial release. Its dedicated DERP/TLS task adds a
40 KiB bounded stack; it is the reliability cost of accepting traffic when UDP
is blocked or both peers are behind difficult NATs.

Static DRAM remained approximately 39 KiB. Actual heap usage varies with the
tailnet map, active WireGuard sessions, and ESP-IDF network buffers.

## Code and data path

- Release builds use `opt-level = "z"`, fat LTO, one codegen unit, aborting
  panics, and stripped debug information.
- The custom Snow resolver exposes only the algorithms selected by Tailscale's
  current Noise patterns: X25519, ChaCha20-Poly1305, and BLAKE2s. AES-GCM and
  unrelated Noise hashes are not linked.
- Ed25519 precomputed signing tables are disabled because the firmware only
  derives its network-lock public key during control registration.
- WireGuard transport supports caller-owned reusable buffers. The reference
  data plane allocates its inbound and outbound packet buffers once.
- ICMP echo replies are formed in place.
- ACL IP patterns and peer AllowedIPs are compiled when a network map arrives,
  instead of parsing strings for every authenticated packet.
- Replay caches and peer timestamp maps use fixed binary values rather than
  heap-allocated hexadecimal strings.

## Idle power and networking

- ESP-IDF dynamic frequency scaling runs the CPU between 40 and 160 MHz.
- Tickless idle and automatic light sleep are enabled.
- Wi-Fi modem sleep remains enabled; incoming traffic may wait for the next
  DTIM beacon. A 10-packet live ICMP test had no loss, with latency consistent
  with the access point's roughly 300 ms DTIM interval.
- The control-plane TLS key is cached for six hours. A resumable Noise/HTTP2
  map stream replaces periodic polls and only reconnects for endpoint changes,
  outages, or server-directed closure.
- STUN refresh remains at 20 seconds because reliable inbound reachability is
  more important than saving one small UDP packet on routers with short NAT
  timeouts.

No current figure is quoted without an external power meter. Light sleep and
modem sleep are enabled and live-tested, but board regulator, LEDs, USB, access
point DTIM, signal strength, and traffic dominate wall-power measurements.

## Memory configuration

- Allocations of 4 KiB or larger may use PSRAM, keeping cryptographic working
  sets in fast internal RAM while moving large control responses outward.
- HTTP fallback resources are capped at two sessions, two open sockets, two
  URI handlers, and four response headers.
- Wi-Fi static RX buffers are reduced from ten to six; dynamic RX/TX pools are
  capped at sixteen. This is appropriate for control messages and tiny UDP
  application packets, not high-throughput subnet routing.
- The full Mozilla CA bundle is replaced by ESP-IDF's common certificate
  bundle. A custom coordination server may require restoring the full bundle
  or embedding its exact trust anchor.

## Deliberate limits

Do not copy these settings blindly into a throughput-oriented VPN, camera, OTA
downloader, or subnet router. Increase Wi-Fi buffers, stacks, and TCP windows
when application traffic requires them. Applications that can guarantee easy
direct UDP may omit the DERP task to recover its TLS stack and flash cost.
