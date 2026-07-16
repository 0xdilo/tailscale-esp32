# Contributing

Keep changes focused and include tests for protocol behavior. Parsers must have
explicit size limits and malformed unauthenticated packets must fail without
panicking. Do not log or add fixtures containing private keys, auth keys,
tailnet details, public addresses, or Wi-Fi credentials.

Before opening a pull request, run:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo test --manifest-path examples/wake-on-lan/Cargo.toml \
  --target x86_64-unknown-linux-gnu
```

Protocol changes should cite the corresponding public Tailscale or WireGuard
source behavior in the pull request description and include an interop test
where practical.
