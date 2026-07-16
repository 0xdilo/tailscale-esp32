use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce, Tag};
use snow::HandshakeState;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::key::{Machine, PrivateKey, PublicKey};
use super::resolver::noise_builder;

const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
const PROLOGUE_PREFIX: &str = "Tailscale Control Protocol v";
const INITIATION_TYPE: u8 = 1;
const RESPONSE_TYPE: u8 = 2;
const ERROR_TYPE: u8 = 3;
const RECORD_TYPE: u8 = 4;
const INITIATION_PAYLOAD_LEN: usize = 96;
const RESPONSE_PAYLOAD_LEN: usize = 48;
const MAX_FRAME_LEN: usize = 4096;
pub const MAX_PLAINTEXT_LEN: usize = MAX_FRAME_LEN - 3 - 16;

pub struct NoiseInitiator {
    version: u16,
    state: HandshakeState,
}

impl NoiseInitiator {
    pub fn new(
        machine_key: &PrivateKey<Machine>,
        control_key: PublicKey<Machine>,
        version: u16,
    ) -> Result<Self, NoiseError> {
        Self::build(machine_key, control_key, version, None)
    }

    fn build(
        machine_key: &PrivateKey<Machine>,
        control_key: PublicKey<Machine>,
        version: u16,
        fixed_ephemeral: Option<&[u8; 32]>,
    ) -> Result<Self, NoiseError> {
        let params = NOISE_PATTERN.parse()?;
        let prologue = format!("{PROLOGUE_PREFIX}{version}");
        let mut builder = noise_builder(params)
            .local_private_key(machine_key.as_bytes())
            .remote_public_key(control_key.as_bytes())
            .prologue(prologue.as_bytes());
        if let Some(ephemeral) = fixed_ephemeral {
            builder = builder.fixed_ephemeral_key_for_testing_only(ephemeral);
        }
        Ok(Self {
            version,
            state: builder.build_initiator()?,
        })
    }

    pub fn initiation(&mut self) -> Result<[u8; 101], NoiseError> {
        let mut frame = [0_u8; 101];
        frame[..2].copy_from_slice(&self.version.to_be_bytes());
        frame[2] = INITIATION_TYPE;
        frame[3..5].copy_from_slice(&(INITIATION_PAYLOAD_LEN as u16).to_be_bytes());
        let written = self.state.write_message(&[], &mut frame[5..])?;
        if written != INITIATION_PAYLOAD_LEN {
            return Err(NoiseError::UnexpectedHandshakeLength(written));
        }
        Ok(frame)
    }

    pub fn finish(mut self, response: &[u8]) -> Result<NoiseTransport, NoiseError> {
        let payload = parse_frame(response, RESPONSE_TYPE, RESPONSE_PAYLOAD_LEN)?;
        let mut empty = [];
        let read = self.state.read_message(payload, &mut empty)?;
        if read != 0 || !self.state.is_handshake_finished() {
            return Err(NoiseError::HandshakeIncomplete);
        }
        let (tx_key, rx_key) = self.state.dangerously_get_raw_split();
        Ok(NoiseTransport::from_split(tx_key, rx_key))
    }

    #[cfg(test)]
    fn new_with_ephemeral(
        machine_key: &PrivateKey<Machine>,
        control_key: PublicKey<Machine>,
        version: u16,
        fixed_ephemeral: &[u8; 32],
    ) -> Result<Self, NoiseError> {
        Self::build(machine_key, control_key, version, Some(fixed_ephemeral))
    }
}

pub struct NoiseTransport {
    tx: TransportCipher,
    rx: TransportCipher,
}

impl NoiseTransport {
    fn from_split(tx_key: [u8; 32], rx_key: [u8; 32]) -> Self {
        Self {
            tx: TransportCipher::new(tx_key),
            rx: TransportCipher::new(rx_key),
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if plaintext.len() > MAX_PLAINTEXT_LEN {
            return Err(NoiseError::PlaintextTooLarge(plaintext.len()));
        }
        let mut frame = vec![0_u8; plaintext.len() + 3];
        frame[0] = RECORD_TYPE;
        frame[3..].copy_from_slice(plaintext);
        self.tx.encrypt(&mut frame)?;
        let payload_len = frame.len() - 3;
        frame[1..3].copy_from_slice(&(payload_len as u16).to_be_bytes());
        Ok(frame)
    }

    pub fn decrypt(&mut self, frame: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let payload = parse_record(frame)?;
        let mut plaintext = payload.to_vec();
        self.rx.decrypt(&mut plaintext)?;
        Ok(plaintext)
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct TransportCipher {
    key: [u8; 32],
    nonce: u64,
}

impl TransportCipher {
    fn new(key: [u8; 32]) -> Self {
        Self { key, nonce: 0 }
    }

    fn encrypt(&mut self, frame: &mut Vec<u8>) -> Result<(), NoiseError> {
        let nonce = self.current_nonce()?;
        let cipher = ChaCha20Poly1305::new((&self.key).into());
        let tag = cipher
            .encrypt_in_place_detached(&nonce, &[], &mut frame[3..])
            .map_err(|_| NoiseError::TransportCrypto)?;
        frame.extend_from_slice(&tag);
        self.nonce += 1;
        Ok(())
    }

    fn decrypt(&mut self, ciphertext: &mut Vec<u8>) -> Result<(), NoiseError> {
        let nonce = self.current_nonce()?;
        let tag_start = ciphertext
            .len()
            .checked_sub(16)
            .ok_or(NoiseError::TruncatedFrame)?;
        let tag = Tag::clone_from_slice(&ciphertext[tag_start..]);
        ciphertext.truncate(tag_start);
        let cipher = ChaCha20Poly1305::new((&self.key).into());
        let result = cipher.decrypt_in_place_detached(&nonce, &[], ciphertext, &tag);
        self.nonce += 1;
        result.map_err(|_| NoiseError::TransportCrypto)
    }

    fn current_nonce(&self) -> Result<Nonce, NoiseError> {
        if self.nonce == u64::MAX {
            return Err(NoiseError::NonceExhausted);
        }
        let mut nonce = [0_u8; 12];
        nonce[4..].copy_from_slice(&self.nonce.to_be_bytes());
        Ok(nonce.into())
    }
}

fn parse_frame(
    frame: &[u8],
    expected_type: u8,
    expected_payload_len: usize,
) -> Result<&[u8], NoiseError> {
    if frame.len() < 3 {
        return Err(NoiseError::TruncatedFrame);
    }
    if frame[0] == ERROR_TYPE {
        return Err(NoiseError::ServerError(
            String::from_utf8_lossy(&frame[3..]).into_owned(),
        ));
    }
    if frame[0] != expected_type {
        return Err(NoiseError::UnexpectedFrameType(frame[0]));
    }
    let declared = u16::from_be_bytes([frame[1], frame[2]]) as usize;
    if declared != expected_payload_len || frame.len() != declared + 3 {
        return Err(NoiseError::InvalidFrameLength {
            declared,
            actual: frame.len().saturating_sub(3),
        });
    }
    Ok(&frame[3..])
}

fn parse_record(frame: &[u8]) -> Result<&[u8], NoiseError> {
    if frame.len() > MAX_FRAME_LEN {
        return Err(NoiseError::CiphertextTooLarge(frame.len()));
    }
    if frame.len() < 3 {
        return Err(NoiseError::TruncatedFrame);
    }
    let declared = u16::from_be_bytes([frame[1], frame[2]]) as usize;
    if frame[0] != RECORD_TYPE {
        return Err(NoiseError::UnexpectedFrameType(frame[0]));
    }
    if declared < 16 || frame.len() != declared + 3 {
        return Err(NoiseError::InvalidFrameLength {
            declared,
            actual: frame.len().saturating_sub(3),
        });
    }
    Ok(&frame[3..])
}

#[derive(Debug, Error)]
pub enum NoiseError {
    #[error("Noise protocol error: {0}")]
    Protocol(#[from] snow::Error),
    #[error("truncated control frame")]
    TruncatedFrame,
    #[error("unexpected control frame type {0}")]
    UnexpectedFrameType(u8),
    #[error("invalid frame length: declared {declared}, actual {actual}")]
    InvalidFrameLength { declared: usize, actual: usize },
    #[error("unexpected handshake payload length {0}")]
    UnexpectedHandshakeLength(usize),
    #[error("server rejected handshake: {0}")]
    ServerError(String),
    #[error("Noise handshake did not finish")]
    HandshakeIncomplete,
    #[error("plaintext is too large: {0} bytes")]
    PlaintextTooLarge(usize),
    #[error("ciphertext frame is too large: {0} bytes")]
    CiphertextTooLarge(usize),
    #[error("control transport authentication failed")]
    TransportCrypto,
    #[error("control transport nonce exhausted")]
    NonceExhausted,
}

#[cfg(test)]
mod tests {
    use chacha20poly1305::aead::{AeadInPlace, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};

    use super::{
        NoiseInitiator, NoiseTransport, TransportCipher, MAX_PLAINTEXT_LEN, NOISE_PATTERN,
        PROLOGUE_PREFIX, RECORD_TYPE, RESPONSE_PAYLOAD_LEN, RESPONSE_TYPE,
    };
    use crate::key::{Machine, PrivateKey};

    const VERSION: u16 = 142;

    #[test]
    fn interoperates_with_a_standard_noise_ik_responder() {
        let machine = PrivateKey::<Machine>::from_bytes([0x11; 32]);
        let control = PrivateKey::<Machine>::from_bytes([0x22; 32]);
        let client_ephemeral = PrivateKey::<Machine>::from_bytes([0x33; 32]);
        let server_ephemeral = PrivateKey::<Machine>::from_bytes([0x44; 32]);

        let mut client = NoiseInitiator::new_with_ephemeral(
            &machine,
            control.public(),
            VERSION,
            client_ephemeral.as_bytes(),
        )
        .unwrap();
        let initiation = client.initiation().unwrap();
        assert_eq!(initiation[0..2], VERSION.to_be_bytes());
        assert_eq!(initiation[2], 1);
        assert_eq!(u16::from_be_bytes([initiation[3], initiation[4]]), 96);

        let params = NOISE_PATTERN.parse().unwrap();
        let prologue = format!("{PROLOGUE_PREFIX}{VERSION}");
        let mut server = crate::resolver::noise_builder(params)
            .local_private_key(control.as_bytes())
            .fixed_ephemeral_key_for_testing_only(server_ephemeral.as_bytes())
            .prologue(prologue.as_bytes())
            .build_responder()
            .unwrap();
        let mut empty = [];
        assert_eq!(
            server.read_message(&initiation[5..], &mut empty).unwrap(),
            0
        );
        let mut response = [0_u8; 51];
        response[0] = RESPONSE_TYPE;
        response[1..3].copy_from_slice(&(RESPONSE_PAYLOAD_LEN as u16).to_be_bytes());
        assert_eq!(server.write_message(&[], &mut response[3..]).unwrap(), 48);

        let (client_to_server, server_to_client) = server.dangerously_get_raw_split();
        let mut client = client.finish(&response).unwrap();
        let mut server = NoiseTransport::from_split(server_to_client, client_to_server);

        for message in [b"first control".as_slice(), b"second control"] {
            let encrypted = client.encrypt(message).unwrap();
            assert_eq!(encrypted[0], RECORD_TYPE);
            assert_eq!(server.decrypt(&encrypted).unwrap(), message);
        }

        for message in [b"first device".as_slice(), b"second device"] {
            let encrypted = server.encrypt(message).unwrap();
            assert_eq!(client.decrypt(&encrypted).unwrap(), message);
        }
    }

    #[test]
    fn transport_nonce_is_big_endian() {
        let key = [7_u8; 32];
        let mut transport = TransportCipher::new(key);
        let mut first = [0_u8; 3].to_vec();
        first.extend_from_slice(b"first");
        transport.encrypt(&mut first).unwrap();

        let mut second = [0_u8; 3].to_vec();
        second.extend_from_slice(b"second");
        transport.encrypt(&mut second).unwrap();

        let mut expected = b"second".to_vec();
        let mut nonce = [0_u8; 12];
        nonce[4..].copy_from_slice(&1_u64.to_be_bytes());
        let cipher = ChaCha20Poly1305::new((&key).into());
        let tag = cipher
            .encrypt_in_place_detached(&Nonce::from(nonce), &[], &mut expected)
            .unwrap();
        expected.extend_from_slice(&tag);
        assert_eq!(&second[3..], expected);
    }

    #[test]
    fn rejects_invalid_framing_before_crypto() {
        let machine = PrivateKey::<Machine>::from_bytes([0x11; 32]);
        let control = PrivateKey::<Machine>::from_bytes([0x22; 32]);
        let client = NoiseInitiator::new(&machine, control.public(), VERSION).unwrap();
        assert!(client.finish(&[2, 0, 48]).is_err());
    }

    #[test]
    fn enforces_tailscale_record_size_limit() {
        assert_eq!(MAX_PLAINTEXT_LEN, 4077);
    }
}
