use std::io::{Read, Write};
use std::net::SocketAddr;

use thiserror::Error;

use super::control::{HostInfo, MapRequest, MapResponse};
use super::identity::{DeviceIdentity, IdentityError, NodeKeyRotation, ENCODED_IDENTITY_LEN};
use super::key::{Node, PublicKey};
use super::netmap::{parse_ip_packet, IpPacket, NetworkMap, PacketError};
use super::paths::{EndpointTracker, PathError, Probe, Route};

pub trait IdentityStorage {
    type Error;

    fn load(&mut self, output: &mut [u8]) -> Result<Option<usize>, Self::Error>;
    fn store_atomically(&mut self, identity: &[u8]) -> Result<(), Self::Error>;
}

pub trait Clock {
    fn monotonic_millis(&self) -> u64;
    fn unix_seconds(&self) -> u64;
}

pub trait TcpConnector {
    type Stream: Read + Write;
    type Error;

    fn connect(&mut self, host: &str, port: u16) -> Result<Self::Stream, Self::Error>;
}

pub trait UdpTransport {
    type Error;

    fn receive_from(&mut self, buffer: &mut [u8]) -> Result<(usize, SocketAddr), Self::Error>;
    fn send_to(&mut self, packet: &[u8], destination: SocketAddr) -> Result<(), Self::Error>;
    fn local_address(&self) -> Result<SocketAddr, Self::Error>;
}

/// Optional packet-device boundary for applications that want TUN semantics.
/// Small appliances can omit it and dispatch authorized packets directly.
pub trait PacketDevice {
    type Error;

    fn receive(&mut self, buffer: &mut [u8]) -> Result<usize, Self::Error>;
    fn send(&mut self, packet: &[u8]) -> Result<(), Self::Error>;
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MapResumeState {
    pub handle: String,
    pub sequence: i64,
}

pub struct TailnetRuntime {
    identity: DeviceIdentity,
    network_map: NetworkMap,
    endpoints: EndpointTracker,
    map_resume: MapResumeState,
}

impl TailnetRuntime {
    pub fn load_or_create<S: IdentityStorage>(
        storage: &mut S,
    ) -> Result<Self, RuntimeStorageError<S::Error>> {
        let mut encoded = [0_u8; ENCODED_IDENTITY_LEN];
        let identity = match storage
            .load(&mut encoded)
            .map_err(RuntimeStorageError::Storage)?
        {
            Some(length) => {
                if length > encoded.len() {
                    return Err(RuntimeStorageError::StoredIdentityTooLarge(length));
                }
                DeviceIdentity::decode(&encoded[..length]).map_err(RuntimeStorageError::Identity)?
            }
            None => {
                let identity = DeviceIdentity::generate().map_err(RuntimeStorageError::Identity)?;
                storage
                    .store_atomically(&identity.encode())
                    .map_err(RuntimeStorageError::Storage)?;
                identity
            }
        };
        Ok(Self {
            identity,
            network_map: NetworkMap::default(),
            endpoints: EndpointTracker::default(),
            map_resume: MapResumeState::default(),
        })
    }

    pub fn identity(&self) -> &DeviceIdentity {
        &self.identity
    }

    pub fn network_map(&self) -> &NetworkMap {
        &self.network_map
    }

    pub fn map_resume(&self) -> &MapResumeState {
        &self.map_resume
    }

    pub fn map_request(&self, version: u16, host_info: HostInfo) -> MapRequest {
        MapRequest::new(
            version,
            self.identity.node_key().public(),
            self.identity.disco_key().public(),
            host_info,
        )
        .streaming()
        .resume(self.map_resume.handle.clone(), self.map_resume.sequence)
    }

    pub fn apply_map(&mut self, response: MapResponse) {
        if !response.map_session_handle.is_empty() {
            self.map_resume
                .handle
                .clone_from(&response.map_session_handle);
        }
        if response.sequence > 0 {
            self.map_resume.sequence = response.sequence;
        }
        self.network_map.apply(response);
        self.endpoints
            .update_from_network_map(self.network_map.peers());
    }

    pub fn prepare_node_key_rotation(&self) -> Result<NodeKeyRotation, IdentityError> {
        self.identity.prepare_node_key_rotation()
    }

    /// Persists an accepted node-key rotation before activating it in memory.
    pub fn commit_node_key_rotation<S: IdentityStorage>(
        &mut self,
        storage: &mut S,
        rotation: &NodeKeyRotation,
    ) -> Result<(), RuntimeStorageError<S::Error>> {
        let rotated = self
            .identity
            .rotated(rotation)
            .map_err(RuntimeStorageError::Identity)?;
        storage
            .store_atomically(&rotated.encode())
            .map_err(RuntimeStorageError::Storage)?;
        self.identity = rotated;
        self.map_resume = MapResumeState::default();
        Ok(())
    }

    pub fn plan_endpoint_probes(
        &mut self,
        peer: PublicKey<Node>,
        now_ms: u64,
    ) -> Result<Vec<Probe>, PathError> {
        self.endpoints.plan_probes(peer, now_ms)
    }

    pub fn record_endpoint_pong(
        &mut self,
        peer: PublicKey<Node>,
        source: SocketAddr,
        transaction_id: [u8; 12],
        now_ms: u64,
    ) -> bool {
        let Some(peer_info) = self
            .network_map
            .peers()
            .find(|candidate| candidate.key == peer)
        else {
            return false;
        };
        self.endpoints
            .record_pong(peer, peer_info.disco_key, source, transaction_id, now_ms)
    }

    pub fn authorize_inbound<'a>(
        &self,
        peer: PublicKey<Node>,
        packet: &'a [u8],
    ) -> Result<AuthorizedPacket<'a>, PacketAuthorizationError> {
        let packet = parse_ip_packet(packet)?;
        if !self.network_map.peer_allows_source(peer, packet.source) {
            return Err(PacketAuthorizationError::SourceRouteDenied);
        }
        let destination_port = packet
            .transport_ports()
            .map_or(0, |(_, destination)| destination);
        if !self.network_map.allows(
            packet.source,
            packet.destination,
            packet.protocol,
            destination_port,
        ) {
            return Err(PacketAuthorizationError::AclDenied);
        }
        Ok(AuthorizedPacket {
            peer,
            packet,
            destination_port,
        })
    }

    pub fn route_outbound<'a>(
        &self,
        packet: &'a [u8],
        now_ms: u64,
    ) -> Result<OutboundPacket<'a>, PacketAuthorizationError> {
        let packet = parse_ip_packet(packet)?;
        let peer = self
            .network_map
            .peer_for_destination(packet.destination)
            .ok_or(PacketAuthorizationError::NoDestinationRoute)?;
        Ok(OutboundPacket {
            peer,
            route: self.endpoints.route(peer, now_ms),
            packet,
        })
    }

    pub fn deliver_to_packet_device<D: PacketDevice>(
        &self,
        device: &mut D,
        peer: PublicKey<Node>,
        packet: &[u8],
    ) -> Result<(), PacketDeliveryError<D::Error>> {
        let authorized = self
            .authorize_inbound(peer, packet)
            .map_err(PacketDeliveryError::Authorization)?;
        device
            .send(authorized.packet.packet)
            .map_err(PacketDeliveryError::Device)
    }
}

pub struct AuthorizedPacket<'a> {
    pub peer: PublicKey<Node>,
    pub packet: IpPacket<'a>,
    pub destination_port: u16,
}

pub struct OutboundPacket<'a> {
    pub peer: PublicKey<Node>,
    pub route: Route,
    pub packet: IpPacket<'a>,
}

#[derive(Debug, Error)]
pub enum RuntimeStorageError<E> {
    #[error("persistent identity storage failed")]
    Storage(E),
    #[error("persistent identity is invalid: {0}")]
    Identity(IdentityError),
    #[error("persistent identity reports an oversized value: {0} bytes")]
    StoredIdentityTooLarge(usize),
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PacketAuthorizationError {
    #[error("invalid inner IP packet: {0}")]
    Packet(#[from] PacketError),
    #[error("packet source is not routed by its authenticated peer")]
    SourceRouteDenied,
    #[error("packet was denied by the tailnet ACL")]
    AclDenied,
    #[error("no tailnet peer routes the packet destination")]
    NoDestinationRoute,
}

#[derive(Debug, Error)]
pub enum PacketDeliveryError<E> {
    #[error("packet authorization failed: {0}")]
    Authorization(PacketAuthorizationError),
    #[error("packet device write failed")]
    Device(E),
}

#[cfg(test)]
mod tests {
    use super::{IdentityStorage, TailnetRuntime};

    #[derive(Default)]
    struct MemoryStorage(Option<Vec<u8>>);

    impl IdentityStorage for MemoryStorage {
        type Error = std::convert::Infallible;

        fn load(&mut self, output: &mut [u8]) -> Result<Option<usize>, Self::Error> {
            let Some(value) = &self.0 else {
                return Ok(None);
            };
            output[..value.len()].copy_from_slice(value);
            Ok(Some(value.len()))
        }

        fn store_atomically(&mut self, identity: &[u8]) -> Result<(), Self::Error> {
            self.0 = Some(identity.to_vec());
            Ok(())
        }
    }

    #[test]
    fn creates_persists_and_rotates_an_identity_atomically() {
        let mut storage = MemoryStorage::default();
        let mut runtime = TailnetRuntime::load_or_create(&mut storage).unwrap();
        let machine = runtime.identity().machine_key().public();
        let old_node = runtime.identity().node_key().public();
        let rotation = runtime.prepare_node_key_rotation().unwrap();
        runtime
            .commit_node_key_rotation(&mut storage, &rotation)
            .unwrap();
        assert_eq!(runtime.identity().machine_key().public(), machine);
        assert_ne!(runtime.identity().node_key().public(), old_node);

        let restored = TailnetRuntime::load_or_create(&mut storage).unwrap();
        assert_eq!(
            restored.identity().node_key().public(),
            runtime.identity().node_key().public()
        );
    }
}
