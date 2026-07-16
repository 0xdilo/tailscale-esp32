use std::time::{SystemTime, UNIX_EPOCH};

use blake2::digest::consts::U16;
use blake2::digest::{KeyInit as BlakeKeyInit, Mac};
use blake2::{Blake2s256, Blake2sMac, Digest};
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, Nonce, Tag};
use snow::HandshakeState;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::key::{Node, PrivateKey, PublicKey};
use super::resolver::noise_builder;

const NOISE_PATTERN: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const PROLOGUE: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
const MAC1_LABEL: &[u8] = b"mac1----";
const INITIATION_TYPE: u32 = 1;
const RESPONSE_TYPE: u32 = 2;
const TRANSPORT_TYPE: u32 = 4;
const INITIATION_LEN: usize = 148;
const RESPONSE_LEN: usize = 92;
const MAX_COUNTER: u64 = 1 << 60;
const TAI64N_BASE: u64 = 0x4000_0000_0000_000a;
const NANO_WHITENER_MASK: u32 = 0x00ff_ffff;

pub struct HandshakeInitiator {
    state: HandshakeState,
    local_index: u32,
    local_public: PublicKey<Node>,
}

pub struct HandshakeResponder;

pub struct HandshakeResponse {
    pub packet: [u8; RESPONSE_LEN],
    pub session: WireGuardSession,
    pub remote_public: PublicKey<Node>,
    pub timestamp: [u8; 12],
}

impl HandshakeResponder {
    pub fn respond(
        local_private: &PrivateKey<Node>,
        initiation: &[u8],
        local_index: u32,
    ) -> Result<HandshakeResponse, WireGuardError> {
        Self::build(local_private, initiation, local_index, None)
    }

    fn build(
        local_private: &PrivateKey<Node>,
        initiation: &[u8],
        local_index: u32,
        fixed_ephemeral: Option<&[u8; 32]>,
    ) -> Result<HandshakeResponse, WireGuardError> {
        if initiation.len() != INITIATION_LEN {
            return Err(WireGuardError::InvalidMessageLength(initiation.len()));
        }
        if u32::from_le_bytes(initiation[..4].try_into().expect("fixed length")) != INITIATION_TYPE
        {
            return Err(WireGuardError::UnexpectedMessageType);
        }
        let remote_index = u32::from_le_bytes(initiation[4..8].try_into().expect("fixed length"));
        if local_index == 0 || remote_index == 0 {
            return Err(WireGuardError::InvalidIndex);
        }
        let local_public = local_private.public();
        verify_mac1(initiation, local_public.as_bytes())?;

        let params = NOISE_PATTERN.parse()?;
        let psk = [0_u8; 32];
        let mut builder = noise_builder(params)
            .prologue(PROLOGUE)
            .local_private_key(local_private.as_bytes())
            .psk(2, &psk);
        if let Some(ephemeral) = fixed_ephemeral {
            builder = builder.fixed_ephemeral_key_for_testing_only(ephemeral);
        }
        let mut state = builder.build_responder()?;
        let mut timestamp = [0_u8; 12];
        let read = state.read_message(&initiation[8..116], &mut timestamp)?;
        if read != timestamp.len() {
            return Err(WireGuardError::UnexpectedHandshakeLength(read));
        }
        let remote_public = PublicKey::<Node>::from_bytes(
            state
                .get_remote_static()
                .ok_or(WireGuardError::MissingRemoteStatic)?
                .try_into()
                .map_err(|_| WireGuardError::MissingRemoteStatic)?,
        );

        let mut packet = [0_u8; RESPONSE_LEN];
        packet[..4].copy_from_slice(&RESPONSE_TYPE.to_le_bytes());
        packet[4..8].copy_from_slice(&local_index.to_le_bytes());
        packet[8..12].copy_from_slice(&remote_index.to_le_bytes());
        let written = state.write_message(&[], &mut packet[12..60])?;
        if written != 48 || !state.is_handshake_finished() {
            return Err(WireGuardError::HandshakeIncomplete);
        }
        add_mac1(&mut packet, remote_public.as_bytes())?;
        let (receive_key, send_key) = state.dangerously_get_raw_split();
        Ok(HandshakeResponse {
            packet,
            session: WireGuardSession {
                send_key,
                receive_key,
                local_index,
                remote_index,
                send_counter: 0,
                replay: ReplayWindow::default(),
            },
            remote_public,
            timestamp,
        })
    }

    #[cfg(test)]
    fn respond_with_ephemeral(
        local_private: &PrivateKey<Node>,
        initiation: &[u8],
        local_index: u32,
        fixed_ephemeral: &[u8; 32],
    ) -> Result<HandshakeResponse, WireGuardError> {
        Self::build(
            local_private,
            initiation,
            local_index,
            Some(fixed_ephemeral),
        )
    }
}

impl HandshakeInitiator {
    pub fn new(
        local_private: &PrivateKey<Node>,
        remote_public: PublicKey<Node>,
        local_index: u32,
    ) -> Result<Self, WireGuardError> {
        Self::build(local_private, remote_public, local_index, None)
    }

    fn build(
        local_private: &PrivateKey<Node>,
        remote_public: PublicKey<Node>,
        local_index: u32,
        fixed_ephemeral: Option<&[u8; 32]>,
    ) -> Result<Self, WireGuardError> {
        if local_index == 0 {
            return Err(WireGuardError::InvalidIndex);
        }
        let params = NOISE_PATTERN.parse()?;
        let psk = [0_u8; 32];
        let mut builder = noise_builder(params)
            .prologue(PROLOGUE)
            .local_private_key(local_private.as_bytes())
            .remote_public_key(remote_public.as_bytes())
            .psk(2, &psk);
        if let Some(ephemeral) = fixed_ephemeral {
            builder = builder.fixed_ephemeral_key_for_testing_only(ephemeral);
        }
        Ok(Self {
            state: builder.build_initiator()?,
            local_index,
            local_public: local_private.public(),
        })
    }

    pub fn initiation(&mut self, now: SystemTime) -> Result<[u8; INITIATION_LEN], WireGuardError> {
        let timestamp = tai64n(now)?;
        let mut message = [0_u8; INITIATION_LEN];
        message[..4].copy_from_slice(&INITIATION_TYPE.to_le_bytes());
        message[4..8].copy_from_slice(&self.local_index.to_le_bytes());
        let written = self.state.write_message(&timestamp, &mut message[8..116])?;
        if written != 108 {
            return Err(WireGuardError::UnexpectedHandshakeLength(written));
        }
        add_mac1(
            &mut message,
            self.state
                .get_remote_static()
                .ok_or(WireGuardError::MissingRemoteStatic)?,
        )?;
        Ok(message)
    }

    pub fn finish(mut self, response: &[u8]) -> Result<WireGuardSession, WireGuardError> {
        if response.len() != RESPONSE_LEN {
            return Err(WireGuardError::InvalidMessageLength(response.len()));
        }
        if u32::from_le_bytes(response[..4].try_into().expect("fixed length")) != RESPONSE_TYPE {
            return Err(WireGuardError::UnexpectedMessageType);
        }
        let remote_index = u32::from_le_bytes(response[4..8].try_into().expect("fixed length"));
        let receiver = u32::from_le_bytes(response[8..12].try_into().expect("fixed length"));
        if remote_index == 0 || receiver != self.local_index {
            return Err(WireGuardError::InvalidIndex);
        }
        verify_mac1(response, self.local_public.as_bytes())?;
        let mut empty = [];
        let read = self.state.read_message(&response[12..60], &mut empty)?;
        if read != 0 || !self.state.is_handshake_finished() {
            return Err(WireGuardError::HandshakeIncomplete);
        }
        let (send_key, receive_key) = self.state.dangerously_get_raw_split();
        Ok(WireGuardSession {
            send_key,
            receive_key,
            local_index: self.local_index,
            remote_index,
            send_counter: 0,
            replay: ReplayWindow::default(),
        })
    }

    #[cfg(test)]
    fn new_with_ephemeral(
        local_private: &PrivateKey<Node>,
        remote_public: PublicKey<Node>,
        local_index: u32,
        fixed_ephemeral: &[u8; 32],
    ) -> Result<Self, WireGuardError> {
        Self::build(
            local_private,
            remote_public,
            local_index,
            Some(fixed_ephemeral),
        )
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct WireGuardSession {
    send_key: [u8; 32],
    receive_key: [u8; 32],
    local_index: u32,
    remote_index: u32,
    send_counter: u64,
    #[zeroize(skip)]
    replay: ReplayWindow,
}

impl WireGuardSession {
    pub fn encrypt(&mut self, packet: &[u8]) -> Result<Vec<u8>, WireGuardError> {
        let mut message = Vec::new();
        self.encrypt_into(packet, &mut message)?;
        Ok(message)
    }

    pub fn encrypt_into(
        &mut self,
        packet: &[u8],
        message: &mut Vec<u8>,
    ) -> Result<(), WireGuardError> {
        if self.send_counter >= MAX_COUNTER {
            return Err(WireGuardError::CounterExhausted);
        }
        let padded_len = packet.len().div_ceil(16) * 16;
        message.clear();
        message.reserve(16 + padded_len + 16);
        message.extend_from_slice(&TRANSPORT_TYPE.to_le_bytes());
        message.extend_from_slice(&self.remote_index.to_le_bytes());
        message.extend_from_slice(&self.send_counter.to_le_bytes());
        message.resize(16 + padded_len, 0);
        message[16..16 + packet.len()].copy_from_slice(packet);
        let cipher = ChaCha20Poly1305::new((&self.send_key).into());
        let tag = cipher
            .encrypt_in_place_detached(&transport_nonce(self.send_counter), &[], &mut message[16..])
            .map_err(|_| WireGuardError::TransportCrypto)?;
        message.extend_from_slice(&tag);
        self.send_counter += 1;
        Ok(())
    }

    pub fn decrypt(&mut self, message: &[u8]) -> Result<Vec<u8>, WireGuardError> {
        let mut plaintext = Vec::new();
        self.decrypt_into(message, &mut plaintext)?;
        Ok(plaintext)
    }

    pub fn decrypt_into(
        &mut self,
        message: &[u8],
        plaintext: &mut Vec<u8>,
    ) -> Result<(), WireGuardError> {
        if message.len() < 32 {
            return Err(WireGuardError::InvalidMessageLength(message.len()));
        }
        if u32::from_le_bytes(message[..4].try_into().expect("fixed length")) != TRANSPORT_TYPE {
            return Err(WireGuardError::UnexpectedMessageType);
        }
        let receiver = u32::from_le_bytes(message[4..8].try_into().expect("fixed length"));
        if receiver != self.local_index {
            return Err(WireGuardError::InvalidIndex);
        }
        let counter = u64::from_le_bytes(message[8..16].try_into().expect("fixed length"));
        if counter >= MAX_COUNTER || !self.replay.can_accept(counter) {
            return Err(WireGuardError::Replay);
        }
        let tag_start = message.len() - 16;
        plaintext.clear();
        plaintext.extend_from_slice(&message[16..tag_start]);
        let tag = Tag::clone_from_slice(&message[tag_start..]);
        let cipher = ChaCha20Poly1305::new((&self.receive_key).into());
        cipher
            .decrypt_in_place_detached(&transport_nonce(counter), &[], plaintext, &tag)
            .map_err(|_| WireGuardError::TransportCrypto)?;
        self.replay.accept(counter);
        Ok(())
    }
}

#[derive(Default)]
struct ReplayWindow {
    highest: Option<u64>,
    bitmap: u128,
}

impl ReplayWindow {
    fn can_accept(&self, counter: u64) -> bool {
        let Some(highest) = self.highest else {
            return true;
        };
        if counter > highest {
            return true;
        }
        let distance = highest - counter;
        distance < 128 && self.bitmap & (1_u128 << distance) == 0
    }

    fn accept(&mut self, counter: u64) {
        let Some(highest) = self.highest else {
            self.highest = Some(counter);
            self.bitmap = 1;
            return;
        };
        if counter > highest {
            let distance = counter - highest;
            self.bitmap = if distance >= 128 {
                1
            } else {
                (self.bitmap << distance) | 1
            };
            self.highest = Some(counter);
        } else {
            self.bitmap |= 1_u128 << (highest - counter);
        }
    }
}

fn tai64n(time: SystemTime) -> Result<[u8; 12], WireGuardError> {
    let elapsed = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| WireGuardError::ClockBeforeEpoch)?;
    let mut timestamp = [0_u8; 12];
    timestamp[..8].copy_from_slice(&(TAI64N_BASE + elapsed.as_secs()).to_be_bytes());
    let nanos = elapsed.subsec_nanos() & !NANO_WHITENER_MASK;
    timestamp[8..].copy_from_slice(&nanos.to_be_bytes());
    Ok(timestamp)
}

fn add_mac1(message: &mut [u8], remote_public: &[u8]) -> Result<(), WireGuardError> {
    let mac_start = message
        .len()
        .checked_sub(32)
        .ok_or(WireGuardError::InvalidMessageLength(message.len()))?;
    let key = mac1_key(remote_public);
    let mac = keyed_blake2s128(&key, &message[..mac_start])?;
    message[mac_start..mac_start + 16].copy_from_slice(&mac);
    Ok(())
}

fn verify_mac1(message: &[u8], local_public: &[u8]) -> Result<(), WireGuardError> {
    let mac_start = message
        .len()
        .checked_sub(32)
        .ok_or(WireGuardError::InvalidMessageLength(message.len()))?;
    let key = mac1_key(local_public);
    let mut verifier = <Blake2sMac<U16> as BlakeKeyInit>::new_from_slice(&key)
        .map_err(|_| WireGuardError::MacKey)?;
    verifier.update(&message[..mac_start]);
    verifier
        .verify_slice(&message[mac_start..mac_start + 16])
        .map_err(|_| WireGuardError::InvalidMac)
}

fn mac1_key(public_key: &[u8]) -> [u8; 32] {
    let mut hash = Blake2s256::new();
    Digest::update(&mut hash, MAC1_LABEL);
    Digest::update(&mut hash, public_key);
    hash.finalize().into()
}

fn keyed_blake2s128(key: &[u8], message: &[u8]) -> Result<[u8; 16], WireGuardError> {
    let mut mac = <Blake2sMac<U16> as BlakeKeyInit>::new_from_slice(key)
        .map_err(|_| WireGuardError::MacKey)?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().into())
}

fn transport_nonce(counter: u64) -> Nonce {
    let mut nonce = [0_u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    nonce.into()
}

#[derive(Debug, Error)]
pub enum WireGuardError {
    #[error("WireGuard Noise error: {0}")]
    Noise(#[from] snow::Error),
    #[error("invalid WireGuard index")]
    InvalidIndex,
    #[error("WireGuard message has invalid length {0}")]
    InvalidMessageLength(usize),
    #[error("unexpected WireGuard message type")]
    UnexpectedMessageType,
    #[error("unexpected WireGuard handshake length {0}")]
    UnexpectedHandshakeLength(usize),
    #[error("WireGuard handshake did not finish")]
    HandshakeIncomplete,
    #[error("WireGuard handshake lost the remote static key")]
    MissingRemoteStatic,
    #[error("WireGuard MAC key initialization failed")]
    MacKey,
    #[error("WireGuard MAC authentication failed")]
    InvalidMac,
    #[error("WireGuard transport authentication failed")]
    TransportCrypto,
    #[error("WireGuard transport counter exhausted")]
    CounterExhausted,
    #[error("WireGuard replayed or stale packet")]
    Replay,
    #[error("system clock is before the Unix epoch")]
    ClockBeforeEpoch,
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use chacha20poly1305::aead::{AeadInPlace, KeyInit};
    use chacha20poly1305::ChaCha20Poly1305;

    use super::{
        add_mac1, transport_nonce, HandshakeInitiator, HandshakeResponder, WireGuardError,
        NOISE_PATTERN, PROLOGUE,
    };
    use crate::key::{Node, PrivateKey};

    #[test]
    fn interoperates_with_wireguard_noise_pattern() {
        let client_private = PrivateKey::<Node>::from_bytes([0x11; 32]);
        let server_private = PrivateKey::<Node>::from_bytes([0x22; 32]);
        let client_ephemeral = PrivateKey::<Node>::from_bytes([0x33; 32]);
        let server_ephemeral = PrivateKey::<Node>::from_bytes([0x44; 32]);
        let mut client = HandshakeInitiator::new_with_ephemeral(
            &client_private,
            server_private.public(),
            7,
            client_ephemeral.as_bytes(),
        )
        .unwrap();
        let now = UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_789);
        let initiation = client.initiation(now).unwrap();
        assert_eq!(initiation.len(), 148);

        let params = NOISE_PATTERN.parse().unwrap();
        let psk = [0_u8; 32];
        let mut server = crate::resolver::noise_builder(params)
            .prologue(PROLOGUE)
            .local_private_key(server_private.as_bytes())
            .psk(2, &psk)
            .fixed_ephemeral_key_for_testing_only(server_ephemeral.as_bytes())
            .build_responder()
            .unwrap();
        let mut timestamp = [0_u8; 12];
        assert_eq!(
            server
                .read_message(&initiation[8..116], &mut timestamp)
                .unwrap(),
            12
        );
        let mut response = [0_u8; 92];
        response[..4].copy_from_slice(&2_u32.to_le_bytes());
        response[4..8].copy_from_slice(&9_u32.to_le_bytes());
        response[8..12].copy_from_slice(&7_u32.to_le_bytes());
        assert_eq!(
            server.write_message(&[], &mut response[12..60]).unwrap(),
            48
        );
        add_mac1(&mut response, client_private.public().as_bytes()).unwrap();
        let (client_to_server, server_to_client) = server.dangerously_get_raw_split();
        let mut client = client.finish(&response).unwrap();

        let encrypted = client.encrypt(b"inner packet").unwrap();
        let mut cleartext = encrypted[16..encrypted.len() - 16].to_vec();
        let tag = chacha20poly1305::Tag::clone_from_slice(&encrypted[encrypted.len() - 16..]);
        ChaCha20Poly1305::new((&client_to_server).into())
            .decrypt_in_place_detached(&transport_nonce(0), &[], &mut cleartext, &tag)
            .unwrap();
        assert_eq!(&cleartext[..12], b"inner packet");

        let mut from_server = Vec::new();
        from_server.extend_from_slice(&4_u32.to_le_bytes());
        from_server.extend_from_slice(&7_u32.to_le_bytes());
        from_server.extend_from_slice(&0_u64.to_le_bytes());
        let mut payload = b"reply".to_vec();
        let tag = ChaCha20Poly1305::new((&server_to_client).into())
            .encrypt_in_place_detached(&transport_nonce(0), &[], &mut payload)
            .unwrap();
        from_server.extend_from_slice(&payload);
        from_server.extend_from_slice(&tag);
        assert_eq!(client.decrypt(&from_server).unwrap(), b"reply");
        assert_eq!(
            client.decrypt(&from_server).unwrap_err().to_string(),
            WireGuardError::Replay.to_string()
        );
    }

    #[test]
    fn responder_and_initiator_exchange_transport_packets() {
        let client_private = PrivateKey::<Node>::from_bytes([0x51; 32]);
        let server_private = PrivateKey::<Node>::from_bytes([0x52; 32]);
        let client_ephemeral = PrivateKey::<Node>::from_bytes([0x53; 32]);
        let server_ephemeral = PrivateKey::<Node>::from_bytes([0x54; 32]);
        let mut client = HandshakeInitiator::new_with_ephemeral(
            &client_private,
            server_private.public(),
            11,
            client_ephemeral.as_bytes(),
        )
        .unwrap();
        let initiation = client
            .initiation(UNIX_EPOCH + Duration::from_secs(1_700_000_000))
            .unwrap();
        let response = HandshakeResponder::respond_with_ephemeral(
            &server_private,
            &initiation,
            12,
            server_ephemeral.as_bytes(),
        )
        .unwrap();
        assert_eq!(response.remote_public, client_private.public());
        let mut server = response.session;
        let mut client = client.finish(&response.packet).unwrap();

        let mut encrypted = Vec::with_capacity(128);
        let mut plaintext = Vec::with_capacity(128);
        client.encrypt_into(b"from client", &mut encrypted).unwrap();
        server.decrypt_into(&encrypted, &mut plaintext).unwrap();
        assert_eq!(&plaintext[..11], b"from client");

        let encrypted_capacity = encrypted.capacity();
        let plaintext_capacity = plaintext.capacity();
        server.encrypt_into(b"from server", &mut encrypted).unwrap();
        client.decrypt_into(&encrypted, &mut plaintext).unwrap();
        assert_eq!(&plaintext[..11], b"from server");
        assert_eq!(encrypted.capacity(), encrypted_capacity);
        assert_eq!(plaintext.capacity(), plaintext_capacity);
    }
}
