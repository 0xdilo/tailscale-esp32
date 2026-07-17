use std::collections::{BTreeMap, VecDeque};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{bail, Context, Result};
use embedded_svc::http::client::Client as HttpClient;
use embedded_svc::http::Method;
use embedded_svc::io::Write;
use embedded_svc::wifi::{AuthMethod, ClientConfiguration, Configuration};
use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::hal::peripherals::Peripherals;
use esp_idf_svc::http::client::{Configuration as HttpConfiguration, EspHttpConnection};
use esp_idf_svc::http::server::EspHttpServer;
use esp_idf_svc::nvs::{EspDefaultNvsPartition, EspNvs, EspNvsPartition, NvsDefault};
use esp_idf_svc::sntp::{EspSntp, SyncStatus};
use esp_idf_svc::tls::{Config as TlsConfiguration, EspTls, InternalSocket};
use esp_idf_svc::wifi::{BlockingWifi, EspWifi};
use log::{info, warn};
use tailscale_esp32::client::ControlConnection;
use tailscale_esp32::control::{
    ControlKeys, HostInfo, MapRequest, MapStreamDecoder, RegisterRequest, RegisterResponse,
    ENDPOINT_TYPE_LOCAL, ENDPOINT_TYPE_PORTMAPPED,
};
use tailscale_esp32::derp::{DerpClient, Event as DerpEvent};
use tailscale_esp32::disco::{open_call_me_maybe, open_ping, seal_ping, seal_pong};
use tailscale_esp32::h2::StreamEvent;
use tailscale_esp32::identity::{DeviceIdentity, ENCODED_IDENTITY_LEN};
use tailscale_esp32::key::{Machine, Node};
use tailscale_esp32::netmap::{icmp_echo_reply_in_place, parse_udp_packet, NetworkMap};
use tailscale_esp32::stun::{binding_request, parse_binding_response};
use tailscale_esp32::wireguard::{HandshakeResponder, WireGuardSession};
use tailscale_esp32::CAPABILITY_VERSION;
use tailscale_esp32_wake_example::{magic_packet, parse_mac, verify_wake_request, DASHBOARD_HTML};

const WIFI_SSID: &str = env!("WIFI_SSID");
const WIFI_PASS: &str = env!("WIFI_PASS");
const WAKE_TOKEN: &str = env!("WAKE_TOKEN");
const WAKE_PATH: &str = env!("WAKE_PATH");
const WAKE_MAC: &str = env!("WAKE_MAC");
const TAILSCALE_HOSTNAME: &str = env!("TAILSCALE_HOSTNAME");
const SERVER_STACK_SIZE: usize = 6144;
const WAKE_REPETITIONS: usize = 3;
const REPLAY_CACHE_SIZE: usize = 64;
const NONCE_BYTES: usize = 16;
const CONTROL_HOST: &str = "controlplane.tailscale.com";
const CONTROL_KEY_URL: &str = "https://controlplane.tailscale.com/key?v=142";
const TAILSCALE_CONTROL_STACK_SIZE: usize = 40_960;
const TAILSCALE_DATA_STACK_SIZE: usize = 24_576;
const TAILSCALE_DERP_STACK_SIZE: usize = 40_960;
const TAILSCALE_WIREGUARD_PORT: u16 = 41_641;
const TAILSCALE_WAKE_PORT: u16 = 41_642;
const STUN_SERVER: &str = "derp1.tailscale.com:3478";
const STUN_INTERVAL: Duration = Duration::from_secs(20);
const CONTROL_RETRY_INTERVAL: Duration = Duration::from_secs(15);
const CONTROL_KEY_MAX_AGE: Duration = Duration::from_secs(6 * 60 * 60);
const PING_WAKE_COOLDOWN: Duration = Duration::from_secs(30);

fn main() -> Result<()> {
    esp_idf_svc::sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();
    validate_configuration()?;
    configure_power_management()?;

    let peripherals = Peripherals::take().context("peripherals already taken")?;
    let sys_loop = EspSystemEventLoop::take().context("system event loop unavailable")?;
    let nvs = EspDefaultNvsPartition::take().context("default NVS partition unavailable")?;
    let tailscale_nvs = nvs.clone();

    let mut wifi = BlockingWifi::wrap(
        EspWifi::new(peripherals.modem, sys_loop.clone(), Some(nvs))?,
        sys_loop,
    )?;
    connect_wifi(&mut wifi)?;

    let sntp = EspSntp::new_default().context("could not start SNTP")?;
    wait_for_time_sync(&sntp)?;

    let ip_info = wifi.wifi().sta_netif().get_ip_info()?;
    info!("dashboard: http://{}/", ip_info.ip);
    info!("wake target: {WAKE_MAC}");

    let mut server = EspHttpServer::new(&esp_idf_svc::http::server::Configuration {
        stack_size: SERVER_STACK_SIZE,
        max_sessions: 2,
        max_open_sockets: 2,
        max_uri_handlers: 3,
        max_resp_headers: 6,
        ..Default::default()
    })?;

    server.fn_handler("/", Method::Get, |request| {
        request
            .into_response(
                200,
                Some("OK"),
                &[
                    ("Content-Type", "text/html; charset=utf-8"),
                    ("Cache-Control", "no-store"),
                    ("X-Content-Type-Options", "nosniff"),
                    (
                        "Content-Security-Policy",
                        "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'",
                    ),
                ],
            )?
            .write_all(DASHBOARD_HTML.as_bytes())
            .map(|_| ())
    })?;

    server.fn_handler("/health", Method::Get, |request| {
        request.into_ok_response()?.write_all(b"ok\n").map(|_| ())
    })?;

    let used_nonces = Arc::new(Mutex::new(VecDeque::<[u8; NONCE_BYTES]>::new()));
    server.fn_handler::<anyhow::Error, _>(WAKE_PATH, Method::Post, {
        let used_nonces = used_nonces.clone();
        move |request| {
            let timestamp = request.header("X-Wake-Timestamp").unwrap_or_default();
            let nonce = request.header("X-Wake-Nonce").unwrap_or_default();
            let signature = request.header("X-Wake-Signature").unwrap_or_default();
            let now = unix_time()?;

            if verify_wake_request(
                WAKE_TOKEN.as_bytes(),
                WAKE_PATH,
                timestamp,
                nonce,
                signature,
                now,
            )
            .is_err()
            {
                warn!("rejected invalid wake signature");
                request
                    .into_status_response(401)?
                    .write_all(b"unauthorized\n")?;
                return Ok(());
            }
            let nonce_key = decode_nonce(nonce).expect("verified nonce has valid hexadecimal data");

            {
                let mut cache = used_nonces
                    .lock()
                    .map_err(|_| anyhow::anyhow!("replay cache lock poisoned"))?;
                if cache.contains(&nonce_key) {
                    warn!("rejected replayed wake request");
                    request
                        .into_status_response(409)?
                        .write_all(b"replayed\n")?;
                    return Ok(());
                }
                cache.push_back(nonce_key);
                if cache.len() > REPLAY_CACHE_SIZE {
                    cache.pop_front();
                }
            }

            send_magic_packet(WAKE_MAC)?;
            request
                .into_ok_response()?
                .write_all(b"wake packet sent\n")?;
            Ok(())
        }
    })?;

    match load_or_create_identity(tailscale_nvs) {
        Ok(keys) => {
            let keys = Arc::new(keys);
            let network_map = Arc::new(Mutex::new(NetworkMap::default()));
            let local_endpoint = format!("{}:{TAILSCALE_WIREGUARD_PORT}", ip_info.ip);
            let endpoints = Arc::new(Mutex::new(vec![(local_endpoint, ENDPOINT_TYPE_LOCAL)]));
            let endpoint_generation = Arc::new(AtomicU32::new(0));
            let preferred_derp = Arc::new(AtomicU16::new(0));
            let (probe_sender, probe_receiver) = sync_channel(8);
            std::thread::Builder::new()
                .name("tailscale-control".into())
                .stack_size(TAILSCALE_CONTROL_STACK_SIZE)
                .spawn({
                    let keys = keys.clone();
                    let network_map = network_map.clone();
                    let endpoints = endpoints.clone();
                    let endpoint_generation = endpoint_generation.clone();
                    let preferred_derp = preferred_derp.clone();
                    move || {
                        tailscale_control_loop(
                            keys,
                            network_map,
                            endpoints,
                            endpoint_generation,
                            preferred_derp,
                        )
                    }
                })
                .context("could not start Tailscale control task")?;
            std::thread::Builder::new()
                .name("tailscale-data".into())
                .stack_size(TAILSCALE_DATA_STACK_SIZE)
                .spawn({
                    let keys = keys.clone();
                    let network_map = network_map.clone();
                    let used_nonces = used_nonces.clone();
                    let endpoint_generation = endpoint_generation.clone();
                    move || {
                        tailscale_data_loop(
                            keys,
                            network_map,
                            endpoints,
                            endpoint_generation,
                            probe_receiver,
                            used_nonces,
                        )
                    }
                })
                .context("could not start Tailscale data task")?;
            std::thread::Builder::new()
                .name("tailscale-derp".into())
                .stack_size(TAILSCALE_DERP_STACK_SIZE)
                .spawn(move || {
                    tailscale_derp_loop(
                        keys,
                        network_map,
                        endpoint_generation,
                        preferred_derp,
                        probe_sender,
                        used_nonces,
                    )
                })
                .context("could not start Tailscale DERP task")?;
        }
        Err(error) => warn!("Tailscale identity unavailable: {error:#}"),
    }

    loop {
        std::thread::sleep(Duration::from_secs(60));
    }
}

fn load_or_create_identity(partition: EspNvsPartition<NvsDefault>) -> Result<DeviceIdentity> {
    let nvs =
        EspNvs::new(partition, "tswake", true).context("could not open Tailscale NVS namespace")?;
    let mut encoded = [0_u8; ENCODED_IDENTITY_LEN];
    if let Some(stored) = nvs.get_blob("device", &mut encoded)? {
        let identity = DeviceIdentity::decode(stored).context("stored identity is invalid")?;
        info!("loaded persistent Tailscale device identity");
        return Ok(identity);
    }
    let identity = DeviceIdentity::generate().context("device identity RNG failed")?;
    nvs.set_blob("device", &identity.encode())
        .context("could not persist Tailscale device identity")?;
    info!("created persistent Tailscale device identity");
    Ok(identity)
}

fn host_info(keys: &DeviceIdentity, preferred_derp: u16) -> HostInfo {
    HostInfo::esp32(TAILSCALE_HOSTNAME, hex(keys.backend_log_id()))
        .with_preferred_derp(preferred_derp)
}

fn tailscale_control_loop(
    keys: Arc<DeviceIdentity>,
    network_map: Arc<Mutex<NetworkMap>>,
    endpoints: Arc<Mutex<Vec<(String, u8)>>>,
    endpoint_generation: Arc<AtomicU32>,
    preferred_derp: Arc<AtomicU16>,
) {
    let mut followup = None;
    let mut cached_control_key = None;
    let mut control_key_fetched_at = None;
    let mut map_resume = MapResume::default();
    loop {
        let key_expired = control_key_fetched_at
            .is_none_or(|fetched: Instant| fetched.elapsed() >= CONTROL_KEY_MAX_AGE);
        if cached_control_key.is_none() || key_expired {
            match fetch_control_key() {
                Ok(key) => {
                    cached_control_key = Some(key);
                    control_key_fetched_at = Some(Instant::now());
                }
                Err(error) => {
                    warn!("Tailscale control key refresh failed: {error:#}");
                    std::thread::sleep(CONTROL_RETRY_INTERVAL);
                    continue;
                }
            }
        }
        let control_key = cached_control_key.expect("control key initialized above");
        if let Err(error) = tailscale_control_session(
            &keys,
            control_key,
            &mut followup,
            &network_map,
            &endpoints,
            &endpoint_generation,
            &preferred_derp,
            &mut map_resume,
        ) {
            warn!("Tailscale control session failed: {error:#}");
        }
        std::thread::sleep(CONTROL_RETRY_INTERVAL);
    }
}

fn tailscale_control_session(
    keys: &DeviceIdentity,
    control_key: tailscale_esp32::key::PublicKey<Machine>,
    followup: &mut Option<String>,
    network_map: &Mutex<NetworkMap>,
    endpoints: &Mutex<Vec<(String, u8)>>,
    endpoint_generation: &AtomicU32,
    preferred_derp: &AtomicU16,
    map_resume: &mut MapResume,
) -> Result<()> {
    let stream =
        TcpStream::connect((CONTROL_HOST, 80)).context("could not connect to Tailscale control")?;
    stream.set_read_timeout(Some(Duration::from_secs(130)))?;
    stream.set_write_timeout(Some(Duration::from_secs(15)))?;
    let mut control = ControlConnection::upgrade(
        stream,
        CONTROL_HOST,
        keys.machine_key(),
        control_key,
        CAPABILITY_VERSION,
    )
    .context("Tailscale control upgrade failed")?;

    let node_key = keys.node_key().public();
    let load_balance_key = node_key.to_string();
    let mut registration = RegisterRequest::new(
        CAPABILITY_VERSION,
        node_key,
        keys.network_lock_key().public(),
        host_info(keys, preferred_derp.load(Ordering::Acquire)),
    );
    if let Some(url) = followup.as_ref() {
        info!("waiting for Tailscale approval at: {url}");
        registration = registration.with_followup(url);
    }
    let registration_response: RegisterResponse = control
        .post_json_decode(
            "/machine/register",
            &registration,
            &[load_balance_key.as_str()],
            64 * 1024,
        )
        .context("Tailscale registration failed")?;
    if !registration_response.error.is_empty() {
        bail!(
            "Tailscale rejected registration: {}",
            registration_response.error
        );
    }
    if !registration_response.machine_authorized {
        if registration_response.auth_url.is_empty() {
            bail!("Tailscale registration is pending without an approval URL");
        }
        *followup = Some(registration_response.auth_url.clone());
        info!(
            "TAILSCALE APPROVAL REQUIRED: {}",
            registration_response.auth_url
        );
        return Ok(());
    }
    *followup = None;

    let advertised_generation = endpoint_generation.load(Ordering::Acquire);
    update_network_map(
        keys,
        node_key,
        &load_balance_key,
        &mut control,
        network_map,
        endpoints,
        preferred_derp,
    )?;
    stream_network_maps(
        keys,
        node_key,
        &load_balance_key,
        &mut control,
        network_map,
        endpoint_generation,
        preferred_derp,
        advertised_generation,
        map_resume,
    )
}

#[derive(Default)]
struct MapResume {
    handle: String,
    sequence: i64,
}

fn stream_network_maps(
    keys: &DeviceIdentity,
    node_key: tailscale_esp32::key::PublicKey<Node>,
    load_balance_key: &str,
    control: &mut ControlConnection<TcpStream>,
    network_map: &Mutex<NetworkMap>,
    endpoint_generation: &AtomicU32,
    preferred_derp: &AtomicU16,
    advertised_generation: u32,
    resume: &mut MapResume,
) -> Result<()> {
    let request = MapRequest::new(
        CAPABILITY_VERSION,
        node_key,
        keys.disco_key().public(),
        host_info(keys, preferred_derp.load(Ordering::Acquire)),
    )
    .streaming()
    .resume(resume.handle.clone(), resume.sequence);
    let mut stream = control
        .start_json_stream("/machine/map", &request, &[load_balance_key])
        .context("could not start streaming Tailscale map")?;
    let mut decoder = MapStreamDecoder::new(1024 * 1024);
    let mut headers_received = false;
    loop {
        match control
            .read_stream_event(&mut stream)
            .context("streaming Tailscale map failed")?
        {
            StreamEvent::Headers {
                status, end_stream, ..
            } => {
                if status != 200 {
                    bail!("streaming Tailscale map returned HTTP {status}");
                }
                if end_stream {
                    bail!("streaming Tailscale map ended before sending data");
                }
                headers_received = true;
            }
            StreamEvent::Data {
                payload,
                end_stream,
            } => {
                if !headers_received {
                    bail!("streaming Tailscale map sent data before HTTP headers");
                }
                let maps = decoder
                    .push(&payload)
                    .context("could not decode streaming Tailscale map")?;
                let mut current = network_map
                    .lock()
                    .map_err(|_| anyhow::anyhow!("network map lock poisoned"))?;
                for map in maps {
                    if !map.map_session_handle.is_empty() {
                        resume.handle.clone_from(&map.map_session_handle);
                    }
                    if map.sequence > 0 {
                        resume.sequence = map.sequence;
                    }
                    current.apply(map);
                }
                drop(current);
                if endpoint_generation.load(Ordering::Acquire) != advertised_generation {
                    bail!("Tailscale endpoints changed; reconnecting the map stream");
                }
                if end_stream {
                    bail!("streaming Tailscale map ended");
                }
            }
        }
    }
}

fn update_network_map(
    keys: &DeviceIdentity,
    node_key: tailscale_esp32::key::PublicKey<Node>,
    load_balance_key: &str,
    control: &mut ControlConnection<TcpStream>,
    network_map: &Mutex<NetworkMap>,
    endpoints: &Mutex<Vec<(String, u8)>>,
    preferred_derp: &AtomicU16,
) -> Result<()> {
    let mut map_request = MapRequest::new(
        CAPABILITY_VERSION,
        node_key,
        keys.disco_key().public(),
        host_info(keys, preferred_derp.load(Ordering::Acquire)),
    );
    let endpoints = endpoints
        .lock()
        .map_err(|_| anyhow::anyhow!("endpoint lock poisoned"))?;
    for (endpoint, kind) in endpoints.iter() {
        map_request.endpoints.push(endpoint.clone());
        map_request.endpoint_types.push(*kind);
    }
    drop(endpoints);
    let response = control
        .post_json(
            "/machine/map",
            &map_request,
            &[load_balance_key],
            1024 * 1024,
        )
        .context("Tailscale map request failed")?;
    if response.status != 200 {
        bail!("Tailscale map request returned HTTP {}", response.status);
    }
    let mut decoder = MapStreamDecoder::new(1024 * 1024);
    let maps = decoder
        .push(&response.body)
        .context("could not decode Tailscale network map")?;
    let first = maps
        .first()
        .context("Tailscale returned an empty network map")?;
    let addresses = first
        .node
        .as_ref()
        .and_then(|node| node.addresses.first())
        .map_or("unknown", String::as_str);
    let peer_count = first.peers.as_ref().map_or(0, Vec::len);
    info!("Tailscale control ready: addresses={addresses}, peers={peer_count}");
    let mut current = network_map
        .lock()
        .map_err(|_| anyhow::anyhow!("network map lock poisoned"))?;
    for map in maps {
        current.apply(map);
    }
    Ok(())
}

struct PeerSession {
    session: WireGuardSession,
    peer_key: tailscale_esp32::key::PublicKey<Node>,
}

struct DataPlaneState {
    sessions: BTreeMap<u32, PeerSession>,
    last_ping_wake: Option<Instant>,
    inner_packet: Vec<u8>,
    outbound_packet: Vec<u8>,
}

struct DirectProbe {
    peer: tailscale_esp32::key::PublicKey<Node>,
    disco_key: tailscale_esp32::key::PublicKey<tailscale_esp32::key::Disco>,
    endpoints: Vec<SocketAddr>,
}

impl DataPlaneState {
    fn new(max_packet_len: usize) -> Self {
        Self {
            sessions: BTreeMap::new(),
            last_ping_wake: None,
            inner_packet: Vec::with_capacity(max_packet_len),
            outbound_packet: Vec::with_capacity(max_packet_len),
        }
    }
}

struct StdTls(EspTls<InternalSocket>);

impl std::io::Read for StdTls {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.0
            .read(buffer)
            .map_err(|error| std::io::Error::other(error.to_string()))
    }
}

impl std::io::Write for StdTls {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.0
            .write(buffer)
            .map_err(|error| std::io::Error::other(error.to_string()))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn tailscale_derp_loop(
    keys: Arc<DeviceIdentity>,
    network_map: Arc<Mutex<NetworkMap>>,
    endpoint_generation: Arc<AtomicU32>,
    preferred_derp: Arc<AtomicU16>,
    probe_sender: SyncSender<DirectProbe>,
    used_nonces: Arc<Mutex<VecDeque<[u8; NONCE_BYTES]>>>,
) {
    loop {
        if let Err(error) = tailscale_derp_session(
            &keys,
            &network_map,
            &endpoint_generation,
            &preferred_derp,
            &probe_sender,
            &used_nonces,
        ) {
            warn!("Tailscale DERP session failed: {error:#}");
        }
        std::thread::sleep(CONTROL_RETRY_INTERVAL);
    }
}

fn tailscale_derp_session(
    keys: &DeviceIdentity,
    network_map: &Mutex<NetworkMap>,
    endpoint_generation: &AtomicU32,
    preferred_derp: &AtomicU16,
    probe_sender: &SyncSender<DirectProbe>,
    used_nonces: &Mutex<VecDeque<[u8; NONCE_BYTES]>>,
) -> Result<()> {
    let (region_id, derp_node) = {
        let map = network_map
            .lock()
            .map_err(|_| anyhow::anyhow!("network map lock poisoned"))?;
        let (region_id, node) = map
            .preferred_derp_node()
            .context("Tailscale map does not have a usable DERP node yet")?;
        (region_id, node.clone())
    };
    if preferred_derp.swap(region_id, Ordering::AcqRel) != region_id {
        endpoint_generation.fetch_add(1, Ordering::Release);
    }
    let certificate_name = if derp_node.cert_name.is_empty() {
        derp_node.host_name.as_str()
    } else {
        derp_node.cert_name.as_str()
    };
    let mut tls = EspTls::new().context("could not initialize DERP TLS")?;
    tls.connect(
        &derp_node.host_name,
        derp_node.relay_port(),
        &TlsConfiguration {
            common_name: Some(certificate_name),
            timeout_ms: 130_000,
            use_crt_bundle_attach: true,
            ..Default::default()
        },
    )
    .with_context(|| format!("could not connect to DERP node {}", derp_node.name))?;
    let mut derp = DerpClient::connect(StdTls(tls), &derp_node.host_name, keys.node_key().clone())
        .context("DERP authentication failed")?;
    if !matches!(derp.receive()?, DerpEvent::ServerInfo(_)) {
        bail!("DERP server did not send its authenticated server information");
    }
    derp.note_preferred(true)?;
    info!(
        "Tailscale DERP connected: {} (region {region_id})",
        derp_node.name
    );

    let mut last_timestamps = BTreeMap::<tailscale_esp32::key::PublicKey<Node>, [u8; 12]>::new();
    let mut state = DataPlaneState::new(2048);
    loop {
        let DerpEvent::Packet { source, payload } = derp.receive()? else {
            continue;
        };
        if payload.len() < 4 {
            continue;
        }
        if payload.starts_with(b"TS\xf0\x9f\x92\xac") {
            let Ok(message) = open_call_me_maybe(keys.disco_key(), &payload) else {
                continue;
            };
            let trusted = network_map
                .lock()
                .map_err(|_| anyhow::anyhow!("network map lock poisoned"))?
                .peer_matches_disco(source, message.sender_disco_key);
            if trusted {
                let _ = probe_sender.try_send(DirectProbe {
                    peer: source,
                    disco_key: message.sender_disco_key,
                    endpoints: message.endpoints,
                });
            }
            continue;
        }
        match u32::from_le_bytes(payload[..4].try_into().expect("length checked")) {
            1 => handle_derp_wireguard_handshake(
                &mut derp,
                keys,
                network_map,
                &mut state.sessions,
                &mut last_timestamps,
                source,
                &payload,
            )?,
            4 => {
                if process_wireguard_transport(network_map, used_nonces, &mut state, &payload)? {
                    derp.send(source, &state.outbound_packet)?;
                }
            }
            _ => {}
        }
    }
}

fn handle_derp_wireguard_handshake<S: std::io::Read + std::io::Write>(
    derp: &mut DerpClient<S>,
    keys: &DeviceIdentity,
    network_map: &Mutex<NetworkMap>,
    sessions: &mut BTreeMap<u32, PeerSession>,
    last_timestamps: &mut BTreeMap<tailscale_esp32::key::PublicKey<Node>, [u8; 12]>,
    derp_source: tailscale_esp32::key::PublicKey<Node>,
    packet: &[u8],
) -> Result<()> {
    let local_index = random_session_index(sessions)?;
    let Ok(response) = HandshakeResponder::respond(keys.node_key(), packet, local_index) else {
        return Ok(());
    };
    if response.remote_public != derp_source {
        return Ok(());
    }
    let peer_exists = network_map
        .lock()
        .map_err(|_| anyhow::anyhow!("network map lock poisoned"))?
        .contains_peer(response.remote_public);
    if !peer_exists
        || last_timestamps
            .get(&response.remote_public)
            .is_some_and(|last| *last >= response.timestamp)
    {
        return Ok(());
    }
    last_timestamps.insert(response.remote_public, response.timestamp);
    derp.send(derp_source, &response.packet)?;
    sessions.insert(
        local_index,
        PeerSession {
            session: response.session,
            peer_key: response.remote_public,
        },
    );
    while sessions.len() > 16 {
        let Some(oldest) = sessions.keys().next().copied() else {
            break;
        };
        sessions.remove(&oldest);
    }
    info!("Tailscale WireGuard session established over DERP");
    Ok(())
}

fn tailscale_data_loop(
    keys: Arc<DeviceIdentity>,
    network_map: Arc<Mutex<NetworkMap>>,
    endpoints: Arc<Mutex<Vec<(String, u8)>>>,
    endpoint_generation: Arc<AtomicU32>,
    probe_receiver: Receiver<DirectProbe>,
    used_nonces: Arc<Mutex<VecDeque<[u8; NONCE_BYTES]>>>,
) {
    loop {
        if let Err(error) = tailscale_data(
            keys.clone(),
            network_map.clone(),
            endpoints.clone(),
            endpoint_generation.clone(),
            &probe_receiver,
            used_nonces.clone(),
        ) {
            warn!("Tailscale data session failed: {error:#}");
        }
        std::thread::sleep(CONTROL_RETRY_INTERVAL);
    }
}

fn tailscale_data(
    keys: Arc<DeviceIdentity>,
    network_map: Arc<Mutex<NetworkMap>>,
    endpoints: Arc<Mutex<Vec<(String, u8)>>>,
    endpoint_generation: Arc<AtomicU32>,
    probe_receiver: &Receiver<DirectProbe>,
    used_nonces: Arc<Mutex<VecDeque<[u8; NONCE_BYTES]>>>,
) -> Result<()> {
    let socket = UdpSocket::bind(("0.0.0.0", TAILSCALE_WIREGUARD_PORT))
        .context("could not bind Tailscale UDP socket")?;
    let mut last_timestamps = BTreeMap::<tailscale_esp32::key::PublicKey<Node>, [u8; 12]>::new();
    let mut packet = [0_u8; 2048];
    let mut state = DataPlaneState::new(packet.len());
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    let stun_server = STUN_SERVER
        .to_socket_addrs()
        .context("could not resolve Tailscale STUN server")?
        .find(SocketAddr::is_ipv4)
        .context("Tailscale STUN server has no IPv4 address")?;
    let mut stun_transaction = [0_u8; 12];
    let mut last_stun = Instant::now()
        .checked_sub(STUN_INTERVAL)
        .unwrap_or_else(Instant::now);
    info!("Tailscale data plane listening on UDP {TAILSCALE_WIREGUARD_PORT}");

    loop {
        while let Ok(probe) = probe_receiver.try_recv() {
            for destination in probe.endpoints {
                let mut transaction_id = [0_u8; 12];
                getrandom::getrandom(&mut transaction_id)
                    .map_err(|error| anyhow::anyhow!("DISCO transaction RNG failed: {error}"))?;
                let packet = seal_ping(
                    keys.disco_key(),
                    probe.disco_key,
                    transaction_id,
                    keys.node_key().public(),
                )?;
                if destination.is_ipv4() {
                    if let Err(error) = socket.send_to(&packet, destination) {
                        warn!("could not send direct-path probe to {destination}: {error}");
                    }
                }
            }
            info!("sent direct-path probes requested by {:?}", probe.peer);
        }
        if last_stun.elapsed() >= STUN_INTERVAL {
            getrandom::getrandom(&mut stun_transaction)
                .map_err(|error| anyhow::anyhow!("STUN transaction RNG failed: {error}"))?;
            socket.send_to(&binding_request(stun_transaction), stun_server)?;
            last_stun = Instant::now();
        }
        let (length, source) = match socket.recv_from(&mut packet) {
            Ok(received) => received,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error).context("Tailscale UDP receive failed"),
        };
        let packet = &packet[..length];
        if source.port() == stun_server.port() {
            if let Ok(public_endpoint) = parse_binding_response(packet, stun_transaction) {
                let public_endpoint = public_endpoint.to_string();
                let mut current = endpoints
                    .lock()
                    .map_err(|_| anyhow::anyhow!("endpoint lock poisoned"))?;
                let changed = current
                    .iter()
                    .find(|(_, kind)| *kind == ENDPOINT_TYPE_PORTMAPPED)
                    .is_none_or(|(endpoint, _)| endpoint != &public_endpoint);
                current.retain(|(_, kind)| *kind != ENDPOINT_TYPE_PORTMAPPED);
                // This socket continuously refreshes an endpoint-independent NAT
                // mapping. Advertising it as port-mapped keeps the endpoint in
                // peer maps; ordinary STUN endpoints are intentionally pruned by
                // control because full Tailscale exchanges them over DERP.
                current.push((public_endpoint.clone(), ENDPOINT_TYPE_PORTMAPPED));
                if changed {
                    endpoint_generation.fetch_add(1, Ordering::Release);
                    info!("Tailscale STUN endpoint discovered: {public_endpoint}");
                }
                continue;
            }
        }
        if packet.starts_with(b"TS\xf0\x9f\x92\xac") {
            handle_disco(&socket, &keys, &network_map, packet, source)?;
            continue;
        }
        if packet.len() < 4 {
            continue;
        }
        match u32::from_le_bytes(packet[..4].try_into().expect("length checked")) {
            1 => handle_wireguard_handshake(
                &socket,
                &keys,
                &network_map,
                &mut state.sessions,
                &mut last_timestamps,
                packet,
                source,
            )?,
            4 => {
                if process_wireguard_transport(&network_map, &used_nonces, &mut state, packet)? {
                    socket.send_to(&state.outbound_packet, source)?;
                }
            }
            _ => {}
        }
    }
}

fn handle_disco(
    socket: &UdpSocket,
    keys: &DeviceIdentity,
    network_map: &Mutex<NetworkMap>,
    packet: &[u8],
    source: SocketAddr,
) -> Result<()> {
    let Ok(ping) = open_ping(keys.disco_key(), packet) else {
        return Ok(());
    };
    let Some(node_key) = ping.node_key else {
        return Ok(());
    };
    let allowed = network_map
        .lock()
        .map_err(|_| anyhow::anyhow!("network map lock poisoned"))?
        .peer_matches_disco(node_key, ping.sender_disco_key);
    if !allowed {
        return Ok(());
    }
    let pong = seal_pong(
        keys.disco_key(),
        ping.sender_disco_key,
        ping.transaction_id,
        source,
    )?;
    socket.send_to(&pong, source)?;
    Ok(())
}

fn handle_wireguard_handshake(
    socket: &UdpSocket,
    keys: &DeviceIdentity,
    network_map: &Mutex<NetworkMap>,
    sessions: &mut BTreeMap<u32, PeerSession>,
    last_timestamps: &mut BTreeMap<tailscale_esp32::key::PublicKey<Node>, [u8; 12]>,
    packet: &[u8],
    source: SocketAddr,
) -> Result<()> {
    let local_index = random_session_index(sessions)?;
    let Ok(response) = HandshakeResponder::respond(keys.node_key(), packet, local_index) else {
        return Ok(());
    };
    let peer_exists = network_map
        .lock()
        .map_err(|_| anyhow::anyhow!("network map lock poisoned"))?
        .contains_peer(response.remote_public);
    if !peer_exists {
        return Ok(());
    }
    if last_timestamps
        .get(&response.remote_public)
        .is_some_and(|last| *last >= response.timestamp)
    {
        return Ok(());
    }
    last_timestamps.insert(response.remote_public, response.timestamp);
    socket.send_to(&response.packet, source)?;
    sessions.insert(
        local_index,
        PeerSession {
            session: response.session,
            peer_key: response.remote_public,
        },
    );
    while sessions.len() > 16 {
        let Some(oldest) = sessions.keys().next().copied() else {
            break;
        };
        sessions.remove(&oldest);
    }
    info!("Tailscale WireGuard session established");
    Ok(())
}

fn process_wireguard_transport(
    network_map: &Mutex<NetworkMap>,
    used_nonces: &Mutex<VecDeque<[u8; NONCE_BYTES]>>,
    state: &mut DataPlaneState,
    packet: &[u8],
) -> Result<bool> {
    if packet.len() < 8 {
        return Ok(false);
    }
    let receiver = u32::from_le_bytes(packet[4..8].try_into().expect("length checked"));
    let Some(peer_session) = state.sessions.get_mut(&receiver) else {
        return Ok(false);
    };
    if peer_session
        .session
        .decrypt_into(packet, &mut state.inner_packet)
        .is_err()
    {
        return Ok(false);
    }
    if let Ok(echo) = icmp_echo_reply_in_place(&mut state.inner_packet) {
        let map = network_map
            .lock()
            .map_err(|_| anyhow::anyhow!("network map lock poisoned"))?;
        let route_allowed = map.peer_allows_source(peer_session.peer_key, echo.source);
        let acl_allowed = map.allows(echo.source, echo.destination, 1, 0);
        drop(map);
        if !route_allowed || !acl_allowed {
            return Ok(false);
        }

        peer_session.session.encrypt_into(
            &state.inner_packet[..echo.packet_len],
            &mut state.outbound_packet,
        )?;
        if state
            .last_ping_wake
            .is_none_or(|last| last.elapsed() >= PING_WAKE_COOLDOWN)
        {
            send_magic_packet(WAKE_MAC)?;
            state.last_ping_wake = Some(Instant::now());
            info!("accepted authenticated Tailscale ping wake request");
        }
        return Ok(true);
    }
    let Ok(udp) = parse_udp_packet(&state.inner_packet) else {
        return Ok(false);
    };
    if udp.destination_port != TAILSCALE_WAKE_PORT {
        return Ok(false);
    }

    let map = network_map
        .lock()
        .map_err(|_| anyhow::anyhow!("network map lock poisoned"))?;
    let route_allowed = map.peer_allows_source(peer_session.peer_key, udp.source);
    let acl_allowed = map.allows(udp.source, udp.destination, 17, udp.destination_port);
    if !route_allowed || !acl_allowed {
        return Ok(false);
    }
    drop(map);

    let Ok(auth) = std::str::from_utf8(udp.payload) else {
        return Ok(false);
    };
    let mut fields = auth.lines();
    let (Some(timestamp), Some(nonce), Some(signature)) =
        (fields.next(), fields.next(), fields.next())
    else {
        return Ok(false);
    };
    let auth_valid = fields.next().is_none()
        && verify_wake_request(
            WAKE_TOKEN.as_bytes(),
            WAKE_PATH,
            timestamp,
            nonce,
            signature,
            unix_time()?,
        )
        .is_ok();
    if !auth_valid {
        return Ok(false);
    }
    let nonce_key = decode_nonce(nonce).expect("verified nonce has valid hexadecimal data");
    let mut cache = used_nonces
        .lock()
        .map_err(|_| anyhow::anyhow!("replay cache lock poisoned"))?;
    if cache.contains(&nonce_key) {
        return Ok(false);
    }
    cache.push_back(nonce_key);
    if cache.len() > REPLAY_CACHE_SIZE {
        cache.pop_front();
    }
    drop(cache);
    send_magic_packet(WAKE_MAC)?;
    info!("accepted authenticated Tailscale wake request");
    Ok(false)
}

fn random_session_index(sessions: &BTreeMap<u32, PeerSession>) -> Result<u32> {
    loop {
        let mut bytes = [0_u8; 4];
        getrandom::getrandom(&mut bytes)
            .map_err(|error| anyhow::anyhow!("session index RNG failed: {error}"))?;
        let index = u32::from_le_bytes(bytes);
        if index != 0 && !sessions.contains_key(&index) {
            return Ok(index);
        }
    }
}

fn decode_nonce(value: &str) -> Option<[u8; NONCE_BYTES]> {
    if value.len() != NONCE_BYTES * 2 {
        return None;
    }
    let mut decoded = [0_u8; NONCE_BYTES];
    for (output, pair) in decoded.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *output = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(decoded)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn fetch_control_key() -> Result<tailscale_esp32::key::PublicKey<Machine>> {
    let configuration = HttpConfiguration {
        crt_bundle_attach: Some(esp_idf_svc::sys::esp_crt_bundle_attach),
        timeout: Some(Duration::from_secs(15)),
        ..Default::default()
    };
    let mut client = HttpClient::wrap(
        EspHttpConnection::new(&configuration).context("HTTPS client initialization failed")?,
    );
    let request = client
        .get(CONTROL_KEY_URL)
        .context("control key HTTPS request failed")?;
    let mut response = request
        .submit()
        .context("control key HTTPS response failed")?;
    if response.status() != 200 {
        bail!("control key endpoint returned HTTP {}", response.status());
    }
    let mut body = Vec::new();
    let mut chunk = [0_u8; 512];
    loop {
        let read = response
            .read(&mut chunk)
            .context("could not read control key response")?;
        if read == 0 {
            break;
        }
        if body.len() + read > 64 * 1024 {
            bail!("control key response exceeded 64 KiB");
        }
        body.extend_from_slice(&chunk[..read]);
    }
    Ok(serde_json::from_slice::<ControlKeys>(&body)
        .context("invalid control key response")?
        .public_key)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn validate_configuration() -> Result<()> {
    if WIFI_SSID.is_empty() {
        bail!("WIFI_SSID must not be empty");
    }
    if WIFI_PASS.len() < 8 {
        bail!("WIFI_PASS must contain at least eight characters");
    }
    if TAILSCALE_HOSTNAME.is_empty() || TAILSCALE_HOSTNAME.len() > 63 {
        bail!("TAILSCALE_HOSTNAME must contain between 1 and 63 characters");
    }
    if WAKE_TOKEN.len() < 32 {
        bail!("WAKE_TOKEN must contain at least 32 characters");
    }
    if !WAKE_PATH.starts_with('/')
        || WAKE_PATH.len() < 17
        || !WAKE_PATH[1..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        bail!("WAKE_PATH must be a slash followed by at least 16 safe characters");
    }
    parse_mac(WAKE_MAC).map_err(anyhow::Error::msg)?;
    Ok(())
}

fn configure_power_management() -> Result<()> {
    let configuration = esp_idf_svc::sys::esp_pm_config_t {
        max_freq_mhz: 160,
        min_freq_mhz: 40,
        light_sleep_enable: true,
    };
    let result = unsafe {
        esp_idf_svc::sys::esp_pm_configure(
            std::ptr::from_ref(&configuration).cast::<std::ffi::c_void>(),
        )
    };
    if result != esp_idf_svc::sys::ESP_OK {
        bail!("power-management configuration failed with ESP-IDF error {result}");
    }
    Ok(())
}

fn wait_for_time_sync(sntp: &EspSntp<'_>) -> Result<()> {
    for _ in 0..150 {
        if sntp.get_sync_status() == SyncStatus::Completed {
            info!("network time synchronized");
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    bail!("network time did not synchronize within 15 seconds")
}

fn unix_time() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs())
}

fn connect_wifi(wifi: &mut BlockingWifi<EspWifi<'static>>) -> Result<()> {
    let configuration = Configuration::Client(ClientConfiguration {
        ssid: WIFI_SSID
            .try_into()
            .map_err(|_| anyhow::anyhow!("WIFI_SSID is too long"))?,
        bssid: None,
        auth_method: AuthMethod::WPA2Personal,
        password: WIFI_PASS
            .try_into()
            .map_err(|_| anyhow::anyhow!("WIFI_PASS is too long"))?,
        channel: None,
        ..Default::default()
    });

    wifi.set_configuration(&configuration)?;
    wifi.start()?;
    info!("Wi-Fi started; connecting to {WIFI_SSID}");
    wifi.connect().context("Wi-Fi association failed")?;
    wifi.wait_netif_up().context("Wi-Fi DHCP failed")?;
    Ok(())
}

fn send_magic_packet(mac_text: &str) -> Result<()> {
    let mac = parse_mac(mac_text).map_err(anyhow::Error::msg)?;
    let packet = magic_packet(mac);
    let socket = UdpSocket::bind("0.0.0.0:0").context("could not bind wake UDP socket")?;
    socket
        .set_broadcast(true)
        .context("could not enable UDP broadcast")?;

    for _ in 0..WAKE_REPETITIONS {
        socket
            .send_to(&packet, "255.255.255.255:9")
            .context("could not broadcast wake packet")?;
        std::thread::sleep(Duration::from_millis(100));
    }

    info!("sent {WAKE_REPETITIONS} magic packets for {mac_text}");
    Ok(())
}
