use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::key::{Disco, Machine, NetworkLock, Node, PublicKey};

pub const ENDPOINT_TYPE_LOCAL: u8 = 1;
pub const ENDPOINT_TYPE_STUN: u8 = 2;
pub const ENDPOINT_TYPE_PORTMAPPED: u8 = 3;
pub const ENDPOINT_TYPE_STUN_WITH_LOCAL_PORT: u8 = 4;
pub const ENDPOINT_TYPE_EXPLICIT: u8 = 5;

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ControlKeys {
    pub legacy_public_key: PublicKey<Machine>,
    pub public_key: PublicKey<Machine>,
}

impl ControlKeys {
    pub fn endpoint(base_url: &str, capability_version: u16) -> String {
        format!(
            "{}/key?v={capability_version}",
            base_url.trim_end_matches('/')
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HostInfo {
    #[serde(rename = "IPNVersion")]
    pub ipn_version: String,
    #[serde(rename = "BackendLogID")]
    pub backend_log_id: String,
    #[serde(rename = "OS")]
    pub os: String,
    #[serde(rename = "OSVersion", skip_serializing_if = "String::is_empty")]
    pub os_version: String,
    #[serde(rename = "DeviceModel")]
    pub device_model: String,
    #[serde(rename = "Hostname")]
    pub hostname: String,
    #[serde(rename = "Machine")]
    pub machine: String,
    #[serde(rename = "GoArch")]
    pub architecture: String,
    #[serde(rename = "NoLogsNoSupport")]
    pub no_logs_no_support: bool,
    #[serde(rename = "Userspace")]
    pub userspace: bool,
}

impl HostInfo {
    pub fn esp32(hostname: impl Into<String>, backend_log_id: impl Into<String>) -> Self {
        Self {
            ipn_version: format!("tailscale-esp32/{}", env!("CARGO_PKG_VERSION")),
            backend_log_id: backend_log_id.into(),
            os: "esp-idf".into(),
            os_version: String::new(),
            device_model: "ESP32-S3".into(),
            hostname: hostname.into(),
            machine: "ESP32-S3".into(),
            architecture: "xtensa".into(),
            no_logs_no_support: true,
            userspace: true,
        }
    }
}

#[derive(Serialize)]
pub struct RegisterAuth {
    #[serde(rename = "AuthKey")]
    auth_key: String,
}

impl RegisterAuth {
    pub fn new(auth_key: impl Into<String>) -> Self {
        Self {
            auth_key: auth_key.into(),
        }
    }
}

#[derive(Serialize)]
pub struct RegisterRequest {
    #[serde(rename = "Version")]
    pub version: u16,
    #[serde(rename = "NodeKey")]
    pub node_key: PublicKey<Node>,
    #[serde(rename = "OldNodeKey")]
    pub old_node_key: PublicKey<Node>,
    #[serde(rename = "NLKey")]
    pub network_lock_key: PublicKey<NetworkLock>,
    #[serde(rename = "Auth", skip_serializing_if = "Option::is_none")]
    auth: Option<RegisterAuth>,
    #[serde(rename = "Hostinfo")]
    pub host_info: HostInfo,
    #[serde(rename = "Followup", skip_serializing_if = "String::is_empty")]
    followup: String,
    #[serde(rename = "Ephemeral", skip_serializing_if = "std::ops::Not::not")]
    pub ephemeral: bool,
}

impl RegisterRequest {
    pub fn new(
        version: u16,
        node_key: PublicKey<Node>,
        network_lock_key: PublicKey<NetworkLock>,
        host_info: HostInfo,
    ) -> Self {
        Self {
            version,
            node_key,
            old_node_key: PublicKey::zero(),
            network_lock_key,
            auth: None,
            host_info,
            followup: String::new(),
            ephemeral: false,
        }
    }

    pub fn with_auth_key(mut self, auth_key: impl Into<String>) -> Self {
        self.auth = Some(RegisterAuth::new(auth_key));
        self
    }

    pub fn with_followup(mut self, followup: impl Into<String>) -> Self {
        self.followup = followup.into();
        self
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
pub struct RegisterResponse {
    #[serde(rename = "NodeKeyExpired", default)]
    pub node_key_expired: bool,
    #[serde(rename = "MachineAuthorized", default)]
    pub machine_authorized: bool,
    #[serde(rename = "AuthURL", default)]
    pub auth_url: String,
    #[serde(rename = "Error", default)]
    pub error: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MapRequest {
    #[serde(rename = "Version")]
    pub version: u16,
    #[serde(rename = "KeepAlive")]
    pub keep_alive: bool,
    #[serde(rename = "NodeKey")]
    pub node_key: PublicKey<Node>,
    #[serde(rename = "DiscoKey")]
    pub disco_key: PublicKey<Disco>,
    #[serde(rename = "Stream")]
    pub stream: bool,
    #[serde(rename = "Hostinfo")]
    pub host_info: HostInfo,
    #[serde(rename = "Endpoints", skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<String>,
    #[serde(rename = "EndpointTypes", skip_serializing_if = "Vec::is_empty")]
    pub endpoint_types: Vec<u8>,
    #[serde(rename = "MapSessionHandle", skip_serializing_if = "String::is_empty")]
    pub map_session_handle: String,
    #[serde(rename = "MapSessionSeq", skip_serializing_if = "is_zero_i64")]
    pub map_session_seq: i64,
    #[serde(rename = "OmitPeers", skip_serializing_if = "std::ops::Not::not")]
    pub omit_peers: bool,
}

impl MapRequest {
    pub fn new(
        version: u16,
        node_key: PublicKey<Node>,
        disco_key: PublicKey<Disco>,
        host_info: HostInfo,
    ) -> Self {
        Self {
            version,
            keep_alive: true,
            node_key,
            disco_key,
            stream: false,
            host_info,
            endpoints: Vec::new(),
            endpoint_types: Vec::new(),
            map_session_handle: String::new(),
            map_session_seq: 0,
            omit_peers: false,
        }
    }

    pub fn streaming(mut self) -> Self {
        self.stream = true;
        self
    }

    pub fn resume(mut self, handle: impl Into<String>, sequence: i64) -> Self {
        self.map_session_handle = handle.into();
        self.map_session_seq = sequence;
        self
    }
}

fn is_zero_i64(value: &i64) -> bool {
    *value == 0
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct NodeInfo {
    #[serde(rename = "ID", default)]
    pub id: u64,
    #[serde(rename = "StableID", default)]
    pub stable_id: String,
    #[serde(rename = "Name", default)]
    pub name: String,
    #[serde(rename = "User", default)]
    pub user: u64,
    #[serde(rename = "Key", default)]
    pub key: PublicKey<Node>,
    #[serde(rename = "Machine", default)]
    pub machine: PublicKey<Machine>,
    #[serde(rename = "DiscoKey", default)]
    pub disco_key: PublicKey<Disco>,
    #[serde(rename = "Addresses", default)]
    pub addresses: Vec<String>,
    #[serde(rename = "AllowedIPs", default)]
    pub allowed_ips: Option<Vec<String>>,
    #[serde(rename = "Endpoints", default)]
    pub endpoints: Vec<String>,
    #[serde(rename = "HomeDERP", default)]
    pub home_derp: u16,
    #[serde(rename = "Online", default)]
    pub online: Option<bool>,
    #[serde(rename = "MachineAuthorized", default)]
    pub machine_authorized: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct PortRange {
    #[serde(rename = "First")]
    pub first: u16,
    #[serde(rename = "Last")]
    pub last: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct NetPortRange {
    #[serde(rename = "IP")]
    pub ip: String,
    #[serde(rename = "Ports")]
    pub ports: PortRange,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct FilterRule {
    #[serde(rename = "SrcIPs", default)]
    pub source_ips: Vec<String>,
    #[serde(rename = "DstPorts", default)]
    pub destination_ports: Vec<NetPortRange>,
    #[serde(rename = "IPProto", default)]
    pub ip_protocols: Vec<i16>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct DerpMap {
    #[serde(rename = "Regions", default)]
    pub regions: BTreeMap<u16, DerpRegion>,
    #[serde(rename = "OmitDefaultRegions", default)]
    pub omit_default_regions: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct DerpRegion {
    #[serde(rename = "RegionID", default)]
    pub region_id: u16,
    #[serde(rename = "RegionCode", default)]
    pub region_code: String,
    #[serde(rename = "RegionName", default)]
    pub region_name: String,
    #[serde(rename = "NoMeasureNoHome", default)]
    pub no_measure_no_home: bool,
    #[serde(rename = "Nodes", default)]
    pub nodes: Vec<DerpNode>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct DerpNode {
    #[serde(rename = "Name", default)]
    pub name: String,
    #[serde(rename = "RegionID", default)]
    pub region_id: u16,
    #[serde(rename = "HostName", default)]
    pub host_name: String,
    #[serde(rename = "CertName", default)]
    pub cert_name: String,
    #[serde(rename = "IPv4", default)]
    pub ipv4: String,
    #[serde(rename = "IPv6", default)]
    pub ipv6: String,
    #[serde(rename = "STUNPort", default)]
    pub stun_port: i16,
    #[serde(rename = "STUNOnly", default)]
    pub stun_only: bool,
    #[serde(rename = "DERPPort", default)]
    pub derp_port: u16,
}

impl DerpNode {
    pub fn relay_port(&self) -> u16 {
        if self.derp_port == 0 {
            443
        } else {
            self.derp_port
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct PeerChange {
    #[serde(rename = "NodeID", default)]
    pub node_id: u64,
    #[serde(rename = "DERPRegion", default)]
    pub derp_region: u16,
    #[serde(rename = "Endpoints", default)]
    pub endpoints: Vec<String>,
    #[serde(rename = "Key", default)]
    pub key: Option<PublicKey<Node>>,
    #[serde(rename = "DiscoKey", default)]
    pub disco_key: Option<PublicKey<Disco>>,
    #[serde(rename = "Online", default)]
    pub online: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct MapResponse {
    #[serde(rename = "MapSessionHandle", default)]
    pub map_session_handle: String,
    #[serde(rename = "Seq", default)]
    pub sequence: i64,
    #[serde(rename = "KeepAlive", default)]
    pub keep_alive: bool,
    #[serde(rename = "Node", default)]
    pub node: Option<NodeInfo>,
    #[serde(rename = "Peers", default)]
    pub peers: Option<Vec<NodeInfo>>,
    #[serde(rename = "PeersChanged", default)]
    pub peers_changed: Vec<NodeInfo>,
    #[serde(rename = "PeersRemoved", default)]
    pub peers_removed: Vec<u64>,
    #[serde(rename = "PeersChangedPatch", default)]
    pub peers_changed_patch: Vec<PeerChange>,
    #[serde(rename = "DERPMap", default)]
    pub derp_map: Option<DerpMap>,
    #[serde(rename = "PacketFilter", default)]
    pub packet_filter: Option<Vec<FilterRule>>,
    #[serde(rename = "PacketFilters", default)]
    pub packet_filters: BTreeMap<String, Option<Vec<FilterRule>>>,
}

pub struct MapStreamDecoder {
    buffer: Vec<u8>,
    max_message_len: usize,
}

impl MapStreamDecoder {
    pub fn new(max_message_len: usize) -> Self {
        Self {
            buffer: Vec::new(),
            max_message_len,
        }
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<MapResponse>, MapDecodeError> {
        self.buffer.extend_from_slice(bytes);
        let mut responses = Vec::new();
        loop {
            if self.buffer.len() < 4 {
                break;
            }
            let message_len = u32::from_le_bytes(
                self.buffer[..4]
                    .try_into()
                    .expect("length checked before conversion"),
            ) as usize;
            if message_len > self.max_message_len {
                return Err(MapDecodeError::MessageTooLarge(message_len));
            }
            let frame_len = 4 + message_len;
            if self.buffer.len() < frame_len {
                break;
            }
            let response = serde_json::from_slice(&self.buffer[4..frame_len])?;
            self.buffer.drain(..frame_len);
            responses.push(response);
        }
        Ok(responses)
    }
}

#[derive(Debug, Error)]
pub enum MapDecodeError {
    #[error("network-map message is too large: {0} bytes")]
    MessageTooLarge(usize),
    #[error("invalid network-map JSON: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::{
        ControlKeys, HostInfo, MapRequest, MapStreamDecoder, RegisterRequest, RegisterResponse,
    };
    use crate::key::{Disco, NetworkLock, Node, PublicKey};

    #[test]
    fn parses_current_control_key_response() {
        let response = r#"{
            "legacyPublicKey":"mkey:9e5156a4c65121306dd2d8ed8f92cb8d738e2533011344b522c5d28409bc4970",
            "publicKey":"mkey:7d2792f9c98d753d2042471536801949104c247f95eac770f8fb321595e2173b"
        }"#;
        let keys: ControlKeys = serde_json::from_str(response).unwrap();
        assert_eq!(
            keys.public_key.to_string(),
            "mkey:7d2792f9c98d753d2042471536801949104c247f95eac770f8fb321595e2173b"
        );
    }

    #[test]
    fn creates_versioned_key_endpoint() {
        assert_eq!(
            ControlKeys::endpoint("https://controlplane.tailscale.com/", 142),
            "https://controlplane.tailscale.com/key?v=142"
        );
    }

    #[test]
    fn registration_uses_official_field_names_without_leaking_auth_in_debug() {
        let request = RegisterRequest::new(
            142,
            PublicKey::<Node>::from_bytes([1; 32]),
            PublicKey::<NetworkLock>::from_bytes([2; 32]),
            HostInfo::esp32("esp32-wake", "0123456789abcdef"),
        )
        .with_auth_key("secret");
        let value = serde_json::to_value(request).unwrap();
        assert_eq!(value["Version"], 142);
        assert!(value["NodeKey"].as_str().unwrap().starts_with("nodekey:"));
        assert!(value["NLKey"].as_str().unwrap().starts_with("nlpub:"));
        assert_eq!(value["Auth"]["AuthKey"], "secret");
        assert_eq!(value["Hostinfo"]["DeviceModel"], "ESP32-S3");
    }

    #[test]
    fn parses_interactive_registration_response() {
        let response: RegisterResponse = serde_json::from_str(
            r#"{"MachineAuthorized":false,"AuthURL":"https://login.tailscale.com/a/example"}"#,
        )
        .unwrap();
        assert!(!response.machine_authorized);
        assert!(response
            .auth_url
            .starts_with("https://login.tailscale.com/"));
    }

    #[test]
    fn decodes_fragmented_length_prefixed_map_messages() {
        let json = br#"{"KeepAlive":true}"#;
        let mut encoded = (json.len() as u32).to_le_bytes().to_vec();
        encoded.extend_from_slice(json);
        let mut decoder = MapStreamDecoder::new(1024);
        assert!(decoder.push(&encoded[..5]).unwrap().is_empty());
        let messages = decoder.push(&encoded[5..]).unwrap();
        assert_eq!(messages.len(), 1);
        assert!(messages[0].keep_alive);
    }

    #[test]
    fn serializes_resumable_stream_request() {
        let request = MapRequest::new(
            142,
            PublicKey::<Node>::from_bytes([3; 32]),
            PublicKey::<Disco>::from_bytes([4; 32]),
            HostInfo::esp32("esp32", "backend"),
        )
        .streaming()
        .resume("map-session", 27);
        let value = serde_json::to_value(request).unwrap();
        assert_eq!(value["Stream"], true);
        assert_eq!(value["KeepAlive"], true);
        assert_eq!(value["MapSessionHandle"], "map-session");
        assert_eq!(value["MapSessionSeq"], 27);
    }

    #[test]
    fn parses_derp_map_and_peer_patch() {
        let response = serde_json::from_str::<super::MapResponse>(
            r#"{
                "Seq":9,
                "PeersChangedPatch":[{"NodeID":7,"DERPRegion":2,"Online":true}],
                "DERPMap":{"Regions":{"2":{"RegionID":2,"RegionCode":"nyc","Nodes":[
                    {"Name":"2a","RegionID":2,"HostName":"derp2.tailscale.com"}
                ]}}}
            }"#,
        )
        .unwrap();
        assert_eq!(response.sequence, 9);
        assert_eq!(response.peers_changed_patch[0].node_id, 7);
        let node = &response.derp_map.unwrap().regions[&2].nodes[0];
        assert_eq!(node.host_name, "derp2.tailscale.com");
        assert_eq!(node.relay_port(), 443);
    }
}
