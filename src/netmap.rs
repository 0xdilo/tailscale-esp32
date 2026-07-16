use std::collections::BTreeMap;
use std::net::IpAddr;
use std::net::{Ipv4Addr, Ipv6Addr};

use thiserror::Error;

use super::control::{FilterRule, MapResponse, NodeInfo};
use super::key::{Disco, Node, PublicKey};

const TCP: u8 = 6;
const UDP: u8 = 17;
const ICMP_V4: u8 = 1;
const ICMP_V6: u8 = 58;

#[derive(Default)]
pub struct NetworkMap {
    pub self_node: Option<NodeInfo>,
    peers: BTreeMap<u64, NodeInfo>,
    peer_routes: BTreeMap<PublicKey<Node>, Vec<IpPattern>>,
    filters: BTreeMap<String, Vec<CompiledRule>>,
    filters_received: bool,
}

impl NetworkMap {
    pub fn apply(&mut self, response: MapResponse) {
        if response.keep_alive {
            return;
        }
        if let Some(node) = response.node {
            self.self_node = Some(node);
        }
        if let Some(peers) = response.peers {
            self.peers.clear();
            self.peer_routes.clear();
            for peer in peers {
                self.insert_peer(peer);
            }
        }
        for peer in response.peers_changed {
            self.insert_peer(peer);
        }
        for id in response.peers_removed {
            if let Some(peer) = self.peers.remove(&id) {
                self.peer_routes.remove(&peer.key);
            }
        }

        if let Some(rules) = response.packet_filter {
            self.filters_received = true;
            self.filters.insert(
                "base".into(),
                rules.into_iter().map(CompiledRule::from).collect(),
            );
        }
        if response.packet_filters.contains_key("*")
            && response
                .packet_filters
                .get("*")
                .is_some_and(Option::is_none)
        {
            self.filters_received = true;
            self.filters.clear();
        }
        for (name, rules) in response.packet_filters {
            if name == "*" {
                continue;
            }
            self.filters_received = true;
            match rules {
                Some(rules) => {
                    self.filters
                        .insert(name, rules.into_iter().map(CompiledRule::from).collect());
                }
                None => {
                    self.filters.remove(&name);
                }
            }
        }
    }

    pub fn allows(
        &self,
        source: IpAddr,
        destination: IpAddr,
        protocol: u8,
        destination_port: u16,
    ) -> bool {
        if !self.filters_received {
            return false;
        }
        self.filters.values().flatten().any(|rule| {
            protocol_matches(&rule.ip_protocols, protocol)
                && rule
                    .source_ips
                    .iter()
                    .any(|pattern| pattern.matches(source))
                && rule.destination_ports.iter().any(|destination_rule| {
                    destination_rule.ports.first <= destination_port
                        && destination_port <= destination_rule.ports.last
                        && destination_rule.ip.matches(destination)
                })
        })
    }

    pub fn contains_peer(&self, key: PublicKey<Node>) -> bool {
        self.peer_routes.contains_key(&key)
    }

    pub fn peers(&self) -> impl ExactSizeIterator<Item = &NodeInfo> {
        self.peers.values()
    }

    pub fn peer_matches_disco(
        &self,
        node_key: PublicKey<Node>,
        disco_key: PublicKey<Disco>,
    ) -> bool {
        self.peers
            .values()
            .any(|peer| peer.key == node_key && peer.disco_key == disco_key)
    }

    pub fn peer_allows_source(&self, key: PublicKey<Node>, address: IpAddr) -> bool {
        self.peer_routes
            .get(&key)
            .is_some_and(|routes| routes.iter().any(|route| route.matches(address)))
    }

    fn insert_peer(&mut self, peer: NodeInfo) {
        let key = peer.key;
        let routes = peer
            .allowed_ips
            .as_ref()
            .unwrap_or(&peer.addresses)
            .iter()
            .map(|route| IpPattern::compile(route))
            .collect();
        if let Some(previous) = self.peers.insert(peer.id, peer) {
            self.peer_routes.remove(&previous.key);
        }
        self.peer_routes.insert(key, routes);
    }
}

struct CompiledRule {
    source_ips: Vec<IpPattern>,
    destination_ports: Vec<CompiledNetPortRange>,
    ip_protocols: Vec<i16>,
}

impl From<FilterRule> for CompiledRule {
    fn from(rule: FilterRule) -> Self {
        Self {
            source_ips: rule
                .source_ips
                .iter()
                .map(|pattern| IpPattern::compile(pattern))
                .collect(),
            destination_ports: rule
                .destination_ports
                .into_iter()
                .map(|destination| CompiledNetPortRange {
                    ip: IpPattern::compile(&destination.ip),
                    ports: destination.ports,
                })
                .collect(),
            ip_protocols: rule.ip_protocols,
        }
    }
}

struct CompiledNetPortRange {
    ip: IpPattern,
    ports: super::control::PortRange,
}

enum IpPattern {
    Any,
    Exact(IpAddr),
    Range {
        family: u8,
        first: u128,
        last: u128,
    },
    Prefix {
        family: u8,
        network: u128,
        mask: u128,
    },
    Invalid,
}

impl IpPattern {
    fn compile(pattern: &str) -> Self {
        if pattern == "*" {
            return Self::Any;
        }
        if pattern.starts_with("cap:") {
            return Self::Invalid;
        }
        if let Some((first, last)) = pattern.split_once('-') {
            return match (first.parse::<IpAddr>(), last.parse::<IpAddr>()) {
                (Ok(first), Ok(last)) => {
                    let (family, first) = ip_number(first);
                    let (last_family, last) = ip_number(last);
                    if family == last_family && first <= last {
                        Self::Range {
                            family,
                            first,
                            last,
                        }
                    } else {
                        Self::Invalid
                    }
                }
                _ => Self::Invalid,
            };
        }
        if let Some((network, prefix)) = pattern.split_once('/') {
            return match (network.parse::<IpAddr>(), prefix.parse::<u8>()) {
                (Ok(network), Ok(prefix)) => {
                    let (family, network) = ip_number(network);
                    if prefix > family {
                        Self::Invalid
                    } else {
                        let host_bits = family - prefix;
                        let mask = if host_bits == 128 {
                            0
                        } else {
                            u128::MAX << host_bits
                        };
                        Self::Prefix {
                            family,
                            network: network & mask,
                            mask,
                        }
                    }
                }
                _ => Self::Invalid,
            };
        }
        pattern.parse::<IpAddr>().map_or(Self::Invalid, Self::Exact)
    }

    fn matches(&self, address: IpAddr) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(expected) => *expected == address,
            Self::Range {
                family,
                first,
                last,
            } => {
                let (address_family, address) = ip_number(address);
                *family == address_family && *first <= address && address <= *last
            }
            Self::Prefix {
                family,
                network,
                mask,
            } => {
                let (address_family, address) = ip_number(address);
                *family == address_family && address & mask == *network
            }
            Self::Invalid => false,
        }
    }
}

fn protocol_matches(protocols: &[i16], protocol: u8) -> bool {
    if protocols.is_empty() {
        return matches!(protocol, TCP | UDP | ICMP_V4 | ICMP_V6);
    }
    protocols.contains(&(protocol as i16))
}

fn ip_pattern_matches(pattern: &str, address: IpAddr) -> bool {
    if pattern == "*" {
        return true;
    }
    if pattern.starts_with("cap:") {
        return false;
    }
    if let Some((first, last)) = pattern.split_once('-') {
        return match (first.parse::<IpAddr>(), last.parse::<IpAddr>()) {
            (Ok(first), Ok(last)) => ip_in_range(address, first, last),
            _ => false,
        };
    }
    if let Some((network, prefix)) = pattern.split_once('/') {
        return match (network.parse::<IpAddr>(), prefix.parse::<u8>()) {
            (Ok(network), Ok(prefix)) => ip_in_prefix(address, network, prefix),
            _ => false,
        };
    }
    pattern.parse::<IpAddr>() == Ok(address)
}

fn ip_in_range(address: IpAddr, first: IpAddr, last: IpAddr) -> bool {
    match (ip_number(address), ip_number(first), ip_number(last)) {
        ((family, address), (first_family, first), (last_family, last))
            if family == first_family && family == last_family =>
        {
            first <= address && address <= last
        }
        _ => false,
    }
}

fn ip_in_prefix(address: IpAddr, network: IpAddr, prefix: u8) -> bool {
    let (address_family, address) = ip_number(address);
    let (network_family, network) = ip_number(network);
    if address_family != network_family || prefix > address_family {
        return false;
    }
    let host_bits = address_family - prefix;
    let mask = if host_bits == 128 {
        0
    } else {
        u128::MAX << host_bits
    };
    address & mask == network & mask
}

fn ip_number(address: IpAddr) -> (u8, u128) {
    match address {
        IpAddr::V4(address) => (32, u32::from(address) as u128),
        IpAddr::V6(address) => (128, u128::from(address)),
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PacketError {
    #[error("packet is truncated")]
    Truncated,
    #[error("packet uses an unsupported IP version")]
    UnsupportedIpVersion,
    #[error("packet is not a plain UDP datagram")]
    UnsupportedTransport,
}

pub struct UdpPacket<'a> {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub source_port: u16,
    pub destination_port: u16,
    pub payload: &'a [u8],
}

pub struct IcmpEchoReply {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub packet: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IcmpEchoMeta {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub packet_len: usize,
}

pub fn icmp_echo_reply(packet: &[u8]) -> Result<IcmpEchoReply, PacketError> {
    let mut reply = packet.to_vec();
    let meta = icmp_echo_reply_in_place(&mut reply)?;
    reply.truncate(meta.packet_len);
    Ok(IcmpEchoReply {
        source: meta.source,
        destination: meta.destination,
        packet: reply,
    })
}

pub fn icmp_echo_reply_in_place(packet: &mut [u8]) -> Result<IcmpEchoMeta, PacketError> {
    if packet.len() < 28 || packet[0] >> 4 != 4 {
        return Err(PacketError::UnsupportedIpVersion);
    }
    let header_len = (packet[0] as usize & 0x0f) * 4;
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if header_len < 20 || total_len < header_len + 8 || packet.len() < total_len {
        return Err(PacketError::Truncated);
    }
    if packet[9] != ICMP_V4
        || fragment & 0x3fff != 0
        || packet[header_len] != 8
        || packet[header_len + 1] != 0
    {
        return Err(PacketError::UnsupportedTransport);
    }

    let source = IpAddr::V4(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ));
    let destination = IpAddr::V4(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ));
    packet[12..20].rotate_left(4);
    packet[8] = 64;
    packet[10..12].fill(0);
    let ip_checksum = internet_checksum(&packet[..header_len]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
    packet[header_len] = 0;
    packet[header_len + 2..header_len + 4].fill(0);
    let icmp_checksum = internet_checksum(&packet[header_len..total_len]);
    packet[header_len + 2..header_len + 4].copy_from_slice(&icmp_checksum.to_be_bytes());

    Ok(IcmpEchoMeta {
        source,
        destination,
        packet_len: total_len,
    })
}

pub fn parse_udp_packet(packet: &[u8]) -> Result<UdpPacket<'_>, PacketError> {
    let version = packet.first().ok_or(PacketError::Truncated)? >> 4;
    match version {
        4 => parse_udp_v4(packet),
        6 => parse_udp_v6(packet),
        _ => Err(PacketError::UnsupportedIpVersion),
    }
}

pub fn node_allows_source(node: &NodeInfo, address: IpAddr) -> bool {
    node.allowed_ips
        .as_ref()
        .unwrap_or(&node.addresses)
        .iter()
        .any(|pattern| ip_pattern_matches(pattern, address))
}

fn parse_udp_v4(packet: &[u8]) -> Result<UdpPacket<'_>, PacketError> {
    if packet.len() < 20 {
        return Err(PacketError::Truncated);
    }
    let header_len = (packet[0] as usize & 0x0f) * 4;
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if header_len < 20 || total_len < header_len + 8 || packet.len() < total_len {
        return Err(PacketError::Truncated);
    }
    if packet[9] != UDP || fragment & 0x3fff != 0 {
        return Err(PacketError::UnsupportedTransport);
    }
    let source = IpAddr::V4(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ));
    let destination = IpAddr::V4(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ));
    parse_udp_payload(packet, header_len, total_len, source, destination)
}

fn parse_udp_v6(packet: &[u8]) -> Result<UdpPacket<'_>, PacketError> {
    if packet.len() < 48 {
        return Err(PacketError::Truncated);
    }
    let total_len = 40 + u16::from_be_bytes([packet[4], packet[5]]) as usize;
    if packet[6] != UDP || packet.len() < total_len || total_len < 48 {
        return Err(PacketError::UnsupportedTransport);
    }
    let source = IpAddr::V6(Ipv6Addr::from(
        <[u8; 16]>::try_from(&packet[8..24]).expect("fixed-length slice"),
    ));
    let destination = IpAddr::V6(Ipv6Addr::from(
        <[u8; 16]>::try_from(&packet[24..40]).expect("fixed-length slice"),
    ));
    parse_udp_payload(packet, 40, total_len, source, destination)
}

fn parse_udp_payload(
    packet: &[u8],
    offset: usize,
    total_len: usize,
    source: IpAddr,
    destination: IpAddr,
) -> Result<UdpPacket<'_>, PacketError> {
    let udp = &packet[offset..total_len];
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if udp_len < 8 || udp_len > udp.len() {
        return Err(PacketError::Truncated);
    }
    Ok(UdpPacket {
        source,
        destination,
        source_port: u16::from_be_bytes([udp[0], udp[1]]),
        destination_port: u16::from_be_bytes([udp[2], udp[3]]),
        payload: &udp[8..udp_len],
    })
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = bytes.chunks_exact(2).fold(0_u32, |sum, word| {
        sum + u16::from_be_bytes([word[0], word[1]]) as u32
    });
    if let Some(byte) = bytes.chunks_exact(2).remainder().first() {
        sum += (*byte as u32) << 8;
    }
    while sum > u16::MAX as u32 {
        sum = (sum & u16::MAX as u32) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr};

    use super::{
        icmp_echo_reply, icmp_echo_reply_in_place, internet_checksum, parse_udp_packet, NetworkMap,
    };
    use crate::control::{FilterRule, MapResponse, NetPortRange, NodeInfo, PortRange};
    use crate::key::{Disco, Machine, Node, PublicKey};

    fn response_with_rules(rules: Vec<FilterRule>) -> MapResponse {
        MapResponse {
            keep_alive: false,
            node: None,
            peers: None,
            peers_changed: Vec::new(),
            peers_removed: Vec::new(),
            packet_filter: Some(rules),
            packet_filters: BTreeMap::new(),
        }
    }

    fn wake_rule() -> FilterRule {
        FilterRule {
            source_ips: vec!["100.64.0.0/10".into()],
            destination_ports: vec![NetPortRange {
                ip: "100.100.100.10".into(),
                ports: PortRange {
                    first: 41641,
                    last: 41641,
                },
            }],
            ip_protocols: vec![17],
        }
    }

    fn peer(id: u64, key_byte: u8, allowed_ips: &[&str]) -> NodeInfo {
        NodeInfo {
            id,
            stable_id: format!("peer-{id}"),
            name: format!("peer-{id}"),
            user: 1,
            key: PublicKey::<Node>::from_bytes([key_byte; 32]),
            machine: PublicKey::<Machine>::from_bytes([key_byte; 32]),
            disco_key: PublicKey::<Disco>::from_bytes([key_byte; 32]),
            addresses: vec!["100.64.0.1/32".into()],
            allowed_ips: Some(allowed_ips.iter().map(|value| (*value).into()).collect()),
            endpoints: Vec::new(),
            home_derp: 1,
            online: Some(true),
            machine_authorized: true,
        }
    }

    #[test]
    fn denies_everything_until_a_filter_arrives() {
        let map = NetworkMap::default();
        assert!(!map.allows(
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(100, 100, 100, 10)),
            17,
            41641,
        ));
    }

    #[test]
    fn enforces_source_destination_protocol_and_port() {
        let mut map = NetworkMap::default();
        map.apply(response_with_rules(vec![wake_rule()]));
        let source = "100.64.12.34".parse().unwrap();
        let destination = "100.100.100.10".parse().unwrap();
        assert!(map.allows(source, destination, 17, 41641));
        assert!(!map.allows(source, destination, 6, 41641));
        assert!(!map.allows(source, destination, 17, 80));
        assert!(!map.allows("192.168.1.2".parse().unwrap(), destination, 17, 41641,));
    }

    #[test]
    fn named_filter_clear_is_applied_before_updates() {
        let mut map = NetworkMap::default();
        map.apply(response_with_rules(vec![wake_rule()]));
        let mut packet_filters = BTreeMap::new();
        packet_filters.insert("*".into(), None);
        let mut replacement = wake_rule();
        replacement.source_ips = vec!["100.101.1.1".into()];
        packet_filters.insert("replacement".into(), Some(vec![replacement]));
        map.apply(MapResponse {
            keep_alive: false,
            node: None,
            peers: None,
            peers_changed: Vec::new(),
            peers_removed: Vec::new(),
            packet_filter: None,
            packet_filters,
        });
        assert!(map.allows(
            "100.101.1.1".parse().unwrap(),
            "100.100.100.10".parse().unwrap(),
            17,
            41641,
        ));
        assert!(!map.allows(
            "100.64.12.34".parse().unwrap(),
            "100.100.100.10".parse().unwrap(),
            17,
            41641,
        ));
    }

    #[test]
    fn compiles_peer_routes_and_updates_them_with_map_deltas() {
        let key = PublicKey::<Node>::from_bytes([7; 32]);
        let mut map = NetworkMap::default();
        let mut response = response_with_rules(Vec::new());
        response.peers = Some(vec![peer(7, 7, &["100.70.0.0/16"])]);
        map.apply(response);
        assert!(map.contains_peer(key));
        assert!(map.peer_allows_source(key, "100.70.1.2".parse().unwrap()));
        assert!(!map.peer_allows_source(key, "100.71.1.2".parse().unwrap()));

        let mut changed = response_with_rules(Vec::new());
        changed.peers_changed = vec![peer(7, 7, &["100.71.0.0/16"])];
        map.apply(changed);
        assert!(!map.peer_allows_source(key, "100.70.1.2".parse().unwrap()));
        assert!(map.peer_allows_source(key, "100.71.1.2".parse().unwrap()));

        let mut removed = response_with_rules(Vec::new());
        removed.peers_removed = vec![7];
        map.apply(removed);
        assert!(!map.contains_peer(key));
    }

    #[test]
    fn parses_ipv4_udp_and_ignores_wireguard_padding() {
        let mut packet = vec![0_u8; 20 + 8 + 4];
        packet[0] = 0x45;
        let packet_len = packet.len() as u16;
        packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[100, 64, 0, 1]);
        packet[16..20].copy_from_slice(&[100, 64, 0, 2]);
        packet[20..22].copy_from_slice(&1234_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&41642_u16.to_be_bytes());
        packet[24..26].copy_from_slice(&12_u16.to_be_bytes());
        packet[28..].copy_from_slice(b"wake");
        packet.extend_from_slice(&[0; 12]);

        let parsed = parse_udp_packet(&packet).unwrap();
        assert_eq!(parsed.source.to_string(), "100.64.0.1");
        assert_eq!(parsed.destination.to_string(), "100.64.0.2");
        assert_eq!(parsed.source_port, 1234);
        assert_eq!(parsed.destination_port, 41642);
        assert_eq!(parsed.payload, b"wake");
    }

    #[test]
    fn creates_ipv4_icmp_echo_reply_and_ignores_wireguard_padding() {
        let mut packet = vec![0_u8; 20 + 8 + 4];
        packet[0] = 0x45;
        let packet_len = packet.len() as u16;
        packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
        packet[8] = 64;
        packet[9] = 1;
        packet[12..16].copy_from_slice(&[100, 64, 0, 1]);
        packet[16..20].copy_from_slice(&[100, 64, 0, 2]);
        packet[20] = 8;
        packet[24..26].copy_from_slice(&7_u16.to_be_bytes());
        packet[26..28].copy_from_slice(&9_u16.to_be_bytes());
        packet[28..].copy_from_slice(b"ping");
        let checksum = internet_checksum(&packet[20..]);
        packet[22..24].copy_from_slice(&checksum.to_be_bytes());
        packet.extend_from_slice(&[0; 12]);

        let echo = icmp_echo_reply(&packet).unwrap();
        assert_eq!(echo.source.to_string(), "100.64.0.1");
        assert_eq!(echo.destination.to_string(), "100.64.0.2");
        assert_eq!(&echo.packet[12..16], &[100, 64, 0, 2]);
        assert_eq!(&echo.packet[16..20], &[100, 64, 0, 1]);
        assert_eq!(echo.packet[20], 0);
        assert_eq!(internet_checksum(&echo.packet[..20]), 0);
        assert_eq!(internet_checksum(&echo.packet[20..]), 0);

        let meta = icmp_echo_reply_in_place(&mut packet).unwrap();
        assert_eq!(meta.packet_len, 32);
        assert_eq!(&packet[12..16], &[100, 64, 0, 2]);
        assert_eq!(&packet[16..20], &[100, 64, 0, 1]);
    }
}
