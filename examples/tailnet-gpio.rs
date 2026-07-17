//! Accept an ACL-authorized UDP command and apply it to a local actuator.
//!
//! The packet passed to `authorize_inbound` represents plaintext produced by
//! an authenticated WireGuard peer. Replace `DemoRelay` with an ESP-IDF GPIO
//! driver when integrating this pattern into firmware.

use std::convert::Infallible;
use std::error::Error as StdError;
use std::net::Ipv4Addr;

use tailscale_esp32::control::{FilterRule, MapResponse, NetPortRange, NodeInfo, PortRange};
use tailscale_esp32::key::{Disco, Machine, Node, PublicKey};
use tailscale_esp32::netmap::parse_udp_packet;
use tailscale_esp32::runtime::{IdentityStorage, TailnetRuntime};
use thiserror::Error;

const DEVICE_IP: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);
const OPERATOR_IP: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);
const COMMAND_PORT: u16 = 4242;

fn main() -> Result<(), Box<dyn StdError>> {
    let mut storage = MemoryStorage::default();
    let mut runtime = TailnetRuntime::load_or_create(&mut storage)?;
    let operator = PublicKey::<Node>::from_bytes([1; 32]);
    let map = example_map(&runtime, operator);
    runtime.apply_map(map);

    let packet = ipv4_udp_packet(OPERATOR_IP, DEVICE_IP, 53_000, COMMAND_PORT, b"relay:on");
    let authorized = runtime.authorize_inbound(operator, &packet)?;
    let datagram = parse_udp_packet(authorized.packet.packet)?;

    let mut relay = DemoRelay::default();
    relay.apply(datagram.payload)?;

    println!("authorized command from {}", datagram.source);
    println!("relay enabled: {}", relay.enabled);
    Ok(())
}

#[derive(Default)]
struct DemoRelay {
    enabled: bool,
}

impl DemoRelay {
    fn apply(&mut self, command: &[u8]) -> Result<(), CommandError> {
        self.enabled = match command {
            b"relay:on" => true,
            b"relay:off" => false,
            _ => return Err(CommandError),
        };
        Ok(())
    }
}

#[derive(Debug, Error)]
#[error("unsupported relay command")]
struct CommandError;

#[derive(Default)]
struct MemoryStorage(Option<Vec<u8>>);

impl IdentityStorage for MemoryStorage {
    type Error = Infallible;

    fn load(&mut self, output: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        let Some(identity) = &self.0 else {
            return Ok(None);
        };
        output[..identity.len()].copy_from_slice(identity);
        Ok(Some(identity.len()))
    }

    fn store_atomically(&mut self, identity: &[u8]) -> Result<(), Self::Error> {
        self.0 = Some(identity.to_vec());
        Ok(())
    }
}

fn example_map(runtime: &TailnetRuntime, operator: PublicKey<Node>) -> MapResponse {
    MapResponse {
        node: Some(node(
            2,
            runtime.identity().node_key().public(),
            DEVICE_IP,
            Vec::new(),
            0,
        )),
        peers: Some(vec![node(
            1,
            operator,
            OPERATOR_IP,
            vec!["192.0.2.10:41641".into()],
            4,
        )]),
        packet_filter: Some(vec![FilterRule {
            source_ips: vec![OPERATOR_IP.to_string()],
            destination_ports: vec![NetPortRange {
                ip: DEVICE_IP.to_string(),
                ports: PortRange {
                    first: COMMAND_PORT,
                    last: COMMAND_PORT,
                },
            }],
            ip_protocols: vec![17],
        }]),
        ..MapResponse::default()
    }
}

fn node(
    id: u64,
    key: PublicKey<Node>,
    address: Ipv4Addr,
    endpoints: Vec<String>,
    home_derp: u16,
) -> NodeInfo {
    NodeInfo {
        id,
        stable_id: format!("node-{id}"),
        name: format!("node-{id}"),
        user: 1,
        key,
        machine: PublicKey::<Machine>::from_bytes([id as u8; 32]),
        disco_key: PublicKey::<Disco>::from_bytes([id as u8 + 10; 32]),
        addresses: vec![format!("{address}/32")],
        allowed_ips: None,
        endpoints,
        home_derp,
        legacy_derp: String::new(),
        online: Some(true),
        machine_authorized: true,
    }
}

fn ipv4_udp_packet(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = 20 + 8 + payload.len();
    let mut packet = vec![0_u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    let checksum = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet[20..22].copy_from_slice(&source_port.to_be_bytes());
    packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
    packet[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    packet[28..].copy_from_slice(payload);
    packet
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]) as u32)
        .sum::<u32>();
    if let Some(last) = bytes.chunks_exact(2).remainder().first() {
        sum += (*last as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
