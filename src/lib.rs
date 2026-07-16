//! Native Rust protocol components for constrained Tailscale nodes.
//!
//! This crate contains the control-plane Noise transport, bounded HTTP/2 and
//! HPACK codecs, key types, network-map and ACL handling, WireGuard data-plane
//! primitives, DISCO, and Tailscale-compatible STUN. It is designed around the
//! ESP32's resource constraints but keeps the protocol layer independent of
//! ESP-IDF so it can be tested on a host.
//!
//! The crate is an independent implementation and is not affiliated with or
//! endorsed by Tailscale Inc.

pub mod client;
pub mod control;
pub mod disco;
pub mod h2;
pub mod identity;
pub mod key;
pub mod netmap;
pub mod noise;
mod resolver;
pub mod stun;
pub mod wireguard;

/// Tailscale protocol capability implemented by this release.
pub const CAPABILITY_VERSION: u16 = 142;
