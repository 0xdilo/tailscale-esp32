//! Reply to an authorized sensor request over the best available peer route.
//!
//! This demonstrates DERP fallback first, then promotion to a direct UDP path
//! after an authenticated DISCO probe succeeds.

use std::convert::Infallible;
use std::error::Error;
use std::io;
use std::net::Ipv4Addr;

use tailscale_esp32::control::{FilterRule, MapResponse, NetPortRange, NodeInfo, PortRange};
use tailscale_esp32::key::{Disco, Machine, Node, PublicKey};
use tailscale_esp32::netmap::parse_udp_packet;
use tailscale_esp32::paths::Route;
use tailscale_esp32::runtime::{IdentityStorage, TailnetRuntime};

const SENSOR_IP: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 3);
const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);
const SENSOR_PORT: u16 = 4545;

fn main() -> Result<(), Box<dyn Error>> {
    let mut storage = MemoryStorage::default();
    let mut runtime = TailnetRuntime::load_or_create(&mut storage)?;
    let client = PublicKey::<Node>::from_bytes([7; 32]);
    let map = example_map(&runtime, client);
    runtime.apply_map(map);

    let request = ipv4_udp_packet(CLIENT_IP, SENSOR_IP, 53_001, SENSOR_PORT, b"temperature");
    let authorized = runtime.authorize_inbound(client, &request)?;
    let request = parse_udp_packet(authorized.packet.packet)?;
    if request.payload != b"temperature" {
        return Err(io::Error::other("unsupported sensor request").into());
    }

    let sensor = DemoTemperatureSensor(21.75);
    let payload = format!("{{\"temperature_c\":{:.2}}}", sensor.read_celsius());
    let response = ipv4_udp_packet(
        SENSOR_IP,
        CLIENT_IP,
        SENSOR_PORT,
        request.source_port,
        payload.as_bytes(),
    );

    let relay_route = runtime.route_outbound(&response, 1_000)?.route;
    assert_eq!(relay_route, Route::Derp(4));

    let probe = runtime
        .plan_endpoint_probes(client, 1_000)?
        .into_iter()
        .next()
        .ok_or_else(|| io::Error::other("client did not advertise a direct endpoint"))?;
    assert!(runtime.record_endpoint_pong(client, probe.destination, probe.transaction_id, 1_025,));
    let direct_route = runtime.route_outbound(&response, 1_025)?.route;

    println!("sensor response: {payload}");
    println!("initial route: {relay_route:?}");
    println!("route after authenticated probe: {direct_route:?}");
    Ok(())
}

trait TemperatureSensor {
    fn read_celsius(&self) -> f32;
}

struct DemoTemperatureSensor(f32);

impl TemperatureSensor for DemoTemperatureSensor {
    fn read_celsius(&self) -> f32 {
        self.0
    }
}

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

fn example_map(runtime: &TailnetRuntime, client: PublicKey<Node>) -> MapResponse {
    MapResponse {
        node: Some(node(
            3,
            runtime.identity().node_key().public(),
            SENSOR_IP,
            Vec::new(),
            0,
        )),
        peers: Some(vec![node(
            1,
            client,
            CLIENT_IP,
            vec!["192.0.2.10:41641".into()],
            4,
        )]),
        packet_filter: Some(vec![FilterRule {
            source_ips: vec![CLIENT_IP.to_string()],
            destination_ports: vec![NetPortRange {
                ip: SENSOR_IP.to_string(),
                ports: PortRange {
                    first: SENSOR_PORT,
                    last: SENSOR_PORT,
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
