# Examples

The examples cover two different integration levels.

| Example | Demonstrates | Integration level |
| --- | --- | --- |
| [`wake-on-lan`](wake-on-lan) | Complete Wake-on-LAN appliance with a flash-resident web dashboard | Full ESP32-S3 firmware |
| [`tailnet-gpio.rs`](tailnet-gpio.rs) | ACL-authorized UDP commands for an LED, relay, lock, or pump | Application data plane |
| [`tailnet-sensor.rs`](tailnet-sensor.rs) | Sensor request/reply and automatic direct/DERP route selection | Application data plane |
| [`icmp-status-light.rs`](icmp-status-light.rs) | In-place ICMP echo reply with a local activity indicator | Packet handler |

Run the small examples on a development machine:

```bash
cargo run --example tailnet-gpio
cargo run --example tailnet-sensor
cargo run --example icmp-status-light
```

They use fixed documentation addresses and keys and never contact Tailscale.
Their input represents a packet that the WireGuard session has already
authenticated and decrypted. `TailnetRuntime::authorize_inbound` then enforces
the peer source route and the packet filter received from control before any
application command runs.

For real hardware, replace the demonstration actuator or sensor with the
corresponding ESP-IDF GPIO/I2C driver and call the same handler from the
firmware data-plane loop. Reuse the control, WireGuard, DISCO, and DERP tasks in
[`wake-on-lan`](wake-on-lan) rather than duplicating the protocol plumbing.

Never expose a GPIO command before both WireGuard authentication and tailnet
ACL authorization have succeeded. Physical actuators should additionally have
safe boot defaults, rate limits, and application-specific interlocks.
