use std::collections::{BTreeMap, VecDeque};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{bail, Context, Result};
use embedded_svc::http::client::Client as HttpClient;
use embedded_svc::http::Method;
use embedded_svc::io::Write;
use embedded_svc::wifi::{AuthMethod, ClientConfiguration, Configuration};
use tailscale_esp32::client::ControlConnection;
use tailscale_esp32::control::{
    ControlKeys, HostInfo, MapRequest, MapStreamDecoder, RegisterRequest, RegisterResponse,
    ENDPOINT_TYPE_LOCAL, ENDPOINT_TYPE_PORTMAPPED,
};
use tailscale_esp32::disco::{open_ping, seal_pong};
use tailscale_esp32::identity::{DeviceIdentity, ENCODED_IDENTITY_LEN};
use tailscale_esp32::key::{Machine, Node};
use tailscale_esp32::netmap::{
    icmp_echo_reply, node_allows_source, parse_udp_packet, NetworkMap,
};
use tailscale_esp32::stun::{binding_request, parse_binding_response};
use tailscale_esp32::wireguard::{HandshakeResponder, WireGuardSession};
use tailscale_esp32::CAPABILITY_VERSION;
use tailscale_esp32_wake_example::{magic_packet, parse_mac, verify_wake_request};
use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::hal::peripherals::Peripherals;
use esp_idf_svc::http::client::{Configuration as HttpConfiguration, EspHttpConnection};
use esp_idf_svc::http::server::EspHttpServer;
use esp_idf_svc::nvs::{EspDefaultNvsPartition, EspNvs, EspNvsPartition, NvsDefault};
use esp_idf_svc::sntp::{EspSntp, SyncStatus};
use esp_idf_svc::wifi::{BlockingWifi, EspWifi};
use log::{info, warn};

const WIFI_SSID: &str = env!("WIFI_SSID");
const WIFI_PASS: &str = env!("WIFI_PASS");
const WAKE_TOKEN: &str = env!("WAKE_TOKEN");
const WAKE_PATH: &str = env!("WAKE_PATH");
const WAKE_MAC: &str = env!("WAKE_MAC");
const TAILSCALE_HOSTNAME: &str = env!("TAILSCALE_HOSTNAME");
const SERVER_STACK_SIZE: usize = 8192;
const WAKE_REPETITIONS: usize = 3;
const REPLAY_CACHE_SIZE: usize = 64;
const CONTROL_HOST: &str = "controlplane.tailscale.com";
const CONTROL_KEY_URL: &str = "https://controlplane.tailscale.com/key?v=142";
const TAILSCALE_CONTROL_STACK_SIZE: usize = 49_152;
const TAILSCALE_DATA_STACK_SIZE: usize = 32_768;
const TAILSCALE_WIREGUARD_PORT: u16 = 41_641;
const TAILSCALE_WAKE_PORT: u16 = 41_642;
const STUN_SERVER: &str = "derp1.tailscale.com:3478";
const STUN_INTERVAL: Duration = Duration::from_secs(20);
const PING_WAKE_COOLDOWN: Duration = Duration::from_secs(30);

fn main() -> Result<()> {
    esp_idf_svc::sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();
    validate_configuration()?;

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
    info!("ready: http://{}/health", ip_info.ip);
    info!("wake target: {WAKE_MAC}");

    let mut server = EspHttpServer::new(&esp_idf_svc::http::server::Configuration {
        stack_size: SERVER_STACK_SIZE,
        ..Default::default()
    })?;

    server.fn_handler("/health", Method::Get, |request| {
        request.into_ok_response()?.write_all(b"ok\n").map(|_| ())
    })?;

    let used_nonces = Arc::new(Mutex::new(VecDeque::<String>::new()));
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

            {
                let mut cache = used_nonces
                    .lock()
                    .map_err(|_| anyhow::anyhow!("replay cache lock poisoned"))?;
                if cache.iter().any(|used| used == nonce) {
                    warn!("rejected replayed wake request");
                    request
                        .into_status_response(409)?
                        .write_all(b"replayed\n")?;
                    return Ok(());
                }
                cache.push_back(nonce.to_owned());
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
            std::thread::Builder::new()
                .name("tailscale-control".into())
                .stack_size(TAILSCALE_CONTROL_STACK_SIZE)
                .spawn({
                    let keys = keys.clone();
                    let network_map = network_map.clone();
                    let endpoints = endpoints.clone();
                    move || tailscale_control_loop(keys, network_map, endpoints)
                })
                .context("could not start Tailscale control task")?;
            std::thread::Builder::new()
                .name("tailscale-data".into())
                .stack_size(TAILSCALE_DATA_STACK_SIZE)
                .spawn(move || tailscale_data_loop(keys, network_map, endpoints, used_nonces))
                .context("could not start Tailscale data task")?;
        }
        Err(error) => warn!("Tailscale identity unavailable: {error:#}"),
    }

    loop {
        std::thread::sleep(Duration::from_secs(60));
    }
}

fn load_or_create_identity(partition: EspNvsPartition<NvsDefault>) -> Result<DeviceIdentity> {
    let nvs = EspNvs::new(partition, "tailnode", true)
        .context("could not open Tailscale NVS namespace")?;
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

fn host_info(keys: &DeviceIdentity) -> HostInfo {
    HostInfo::esp32(TAILSCALE_HOSTNAME, hex(keys.backend_log_id()))
}

fn tailscale_control_loop(
    keys: Arc<DeviceIdentity>,
    network_map: Arc<Mutex<NetworkMap>>,
    endpoints: Arc<Mutex<Vec<(String, u8)>>>,
) {
    let mut followup = None;
    loop {
        let delay = match tailscale_control_attempt(&keys, &mut followup, &network_map, &endpoints)
        {
            Ok(true) => Duration::from_secs(60),
            Ok(false) => Duration::from_secs(15),
            Err(error) => {
                warn!("Tailscale control attempt failed: {error:#}");
                Duration::from_secs(15)
            }
        };
        std::thread::sleep(delay);
    }
}

fn tailscale_control_attempt(
    keys: &DeviceIdentity,
    followup: &mut Option<String>,
    network_map: &Mutex<NetworkMap>,
    endpoints: &Mutex<Vec<(String, u8)>>,
) -> Result<bool> {
    let control_key = fetch_control_key()?;
    let stream =
        TcpStream::connect((CONTROL_HOST, 80)).context("could not connect to Tailscale control")?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
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
    let mut registration = RegisterRequest::new(
        CAPABILITY_VERSION,
        node_key,
        keys.network_lock_key().public(),
        host_info(keys),
    );
    if let Some(url) = followup.as_ref() {
        info!("waiting for Tailscale approval at: {url}");
        registration = registration.with_followup(url);
    }
    let registration_response: RegisterResponse = control
        .post_json_decode(
            "/machine/register",
            &registration,
            &[node_key.to_string()],
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
        return Ok(false);
    }
    *followup = None;

    let mut map_request = MapRequest::new(
        CAPABILITY_VERSION,
        node_key,
        keys.disco_key().public(),
        host_info(keys),
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
            &[node_key.to_string()],
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
        .map(|node| node.addresses.join(", "))
        .unwrap_or_else(|| "unknown".into());
    let peer_count = first.peers.as_ref().map_or(0, Vec::len);
    info!("Tailscale control ready: addresses={addresses}, peers={peer_count}");
    let mut current = network_map
        .lock()
        .map_err(|_| anyhow::anyhow!("network map lock poisoned"))?;
    for map in maps {
        current.apply(map);
    }
    Ok(true)
}

struct PeerSession {
    session: WireGuardSession,
    peer_key: tailscale_esp32::key::PublicKey<Node>,
}

fn tailscale_data_loop(
    keys: Arc<DeviceIdentity>,
    network_map: Arc<Mutex<NetworkMap>>,
    endpoints: Arc<Mutex<Vec<(String, u8)>>>,
    used_nonces: Arc<Mutex<VecDeque<String>>>,
) {
    if let Err(error) = tailscale_data(keys, network_map, endpoints, used_nonces) {
        warn!("Tailscale data task stopped: {error:#}");
    }
}

fn tailscale_data(
    keys: Arc<DeviceIdentity>,
    network_map: Arc<Mutex<NetworkMap>>,
    endpoints: Arc<Mutex<Vec<(String, u8)>>>,
    used_nonces: Arc<Mutex<VecDeque<String>>>,
) -> Result<()> {
    let socket = UdpSocket::bind(("0.0.0.0", TAILSCALE_WIREGUARD_PORT))
        .context("could not bind Tailscale UDP socket")?;
    let mut sessions = BTreeMap::<u32, PeerSession>::new();
    let mut last_timestamps = BTreeMap::<String, [u8; 12]>::new();
    let mut last_ping_wake = None;
    let mut packet = [0_u8; 2048];
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
                &mut sessions,
                &mut last_timestamps,
                packet,
                source,
            )?,
            4 => handle_wireguard_transport(
                &socket,
                &network_map,
                &used_nonces,
                &mut sessions,
                &mut last_ping_wake,
                packet,
                source,
            )?,
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
        .peers
        .values()
        .any(|peer| peer.key == node_key && peer.disco_key == ping.sender_disco_key);
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
    last_timestamps: &mut BTreeMap<String, [u8; 12]>,
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
        .peers
        .values()
        .any(|peer| peer.key == response.remote_public);
    if !peer_exists {
        return Ok(());
    }
    let peer_id = response.remote_public.to_string();
    if last_timestamps
        .get(&peer_id)
        .is_some_and(|last| *last >= response.timestamp)
    {
        return Ok(());
    }
    last_timestamps.insert(peer_id, response.timestamp);
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

fn handle_wireguard_transport(
    socket: &UdpSocket,
    network_map: &Mutex<NetworkMap>,
    used_nonces: &Mutex<VecDeque<String>>,
    sessions: &mut BTreeMap<u32, PeerSession>,
    last_ping_wake: &mut Option<Instant>,
    packet: &[u8],
    source: SocketAddr,
) -> Result<()> {
    if packet.len() < 8 {
        return Ok(());
    }
    let receiver = u32::from_le_bytes(packet[4..8].try_into().expect("length checked"));
    let Some(peer_session) = sessions.get_mut(&receiver) else {
        return Ok(());
    };
    let Ok(inner) = peer_session.session.decrypt(packet) else {
        return Ok(());
    };
    if let Ok(echo) = icmp_echo_reply(&inner) {
        let map = network_map
            .lock()
            .map_err(|_| anyhow::anyhow!("network map lock poisoned"))?;
        let Some(peer) = map
            .peers
            .values()
            .find(|peer| peer.key == peer_session.peer_key)
        else {
            return Ok(());
        };
        let route_allowed = node_allows_source(peer, echo.source);
        let acl_allowed = map.allows(echo.source, echo.destination, 1, 0);
        drop(map);
        if !route_allowed || !acl_allowed {
            return Ok(());
        }

        let response = peer_session.session.encrypt(&echo.packet)?;
        socket.send_to(&response, source)?;
        if last_ping_wake.is_none_or(|last| last.elapsed() >= PING_WAKE_COOLDOWN) {
            send_magic_packet(WAKE_MAC)?;
            *last_ping_wake = Some(Instant::now());
            info!("accepted authenticated Tailscale ping wake request");
        }
        return Ok(());
    }
    let Ok(udp) = parse_udp_packet(&inner) else {
        return Ok(());
    };
    if udp.destination_port != TAILSCALE_WAKE_PORT {
        return Ok(());
    }

    let map = network_map
        .lock()
        .map_err(|_| anyhow::anyhow!("network map lock poisoned"))?;
    let Some(peer) = map
        .peers
        .values()
        .find(|peer| peer.key == peer_session.peer_key)
    else {
        return Ok(());
    };
    let route_allowed = node_allows_source(peer, udp.source);
    let acl_allowed = map.allows(udp.source, udp.destination, 17, udp.destination_port);
    if !route_allowed || !acl_allowed {
        return Ok(());
    }
    drop(map);

    let Ok(auth) = std::str::from_utf8(udp.payload) else {
        return Ok(());
    };
    let mut fields = auth.lines();
    let (Some(timestamp), Some(nonce), Some(signature)) =
        (fields.next(), fields.next(), fields.next())
    else {
        return Ok(());
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
        return Ok(());
    }
    let mut cache = used_nonces
        .lock()
        .map_err(|_| anyhow::anyhow!("replay cache lock poisoned"))?;
    if cache.iter().any(|used| used == nonce) {
        return Ok(());
    }
    cache.push_back(nonce.to_owned());
    if cache.len() > REPLAY_CACHE_SIZE {
        cache.pop_front();
    }
    drop(cache);
    send_magic_packet(WAKE_MAC)?;
    info!("accepted authenticated Tailscale wake request");
    Ok(())
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
