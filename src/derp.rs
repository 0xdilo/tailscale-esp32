use std::io::{BufRead, BufReader, Read, Write};

use crypto_box::aead::Aead;
use crypto_box::{PublicKey as BoxPublicKey, SalsaBox, SecretKey as BoxSecretKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::key::{Node, PrivateKey, PublicKey};

pub const MAGIC: &[u8; 8] = b"DERP\xf0\x9f\x94\x91";
pub const PROTOCOL_VERSION: u8 = 2;
pub const MAX_PACKET_SIZE: usize = 64 * 1024;
const MAX_INFO_SIZE: usize = 1024 * 1024;
const MAX_FRAME_SIZE: usize = MAX_INFO_SIZE + 24 + 16;
const MAX_HTTP_HEADERS: usize = 16 * 1024;
const FRAME_SERVER_KEY: u8 = 0x01;
const FRAME_CLIENT_INFO: u8 = 0x02;
const FRAME_SERVER_INFO: u8 = 0x03;
const FRAME_SEND_PACKET: u8 = 0x04;
const FRAME_RECV_PACKET: u8 = 0x05;
const FRAME_KEEP_ALIVE: u8 = 0x06;
const FRAME_NOTE_PREFERRED: u8 = 0x07;
const FRAME_PEER_GONE: u8 = 0x08;
const FRAME_PING: u8 = 0x12;
const FRAME_PONG: u8 = 0x13;
const FRAME_HEALTH: u8 = 0x14;
const FRAME_RESTARTING: u8 = 0x15;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct ServerInfo {
    #[serde(rename = "version", default)]
    pub version: u8,
    #[serde(rename = "TokenBucketBytesPerSecond", default)]
    pub token_bucket_bytes_per_second: u64,
    #[serde(rename = "TokenBucketBytesBurst", default)]
    pub token_bucket_bytes_burst: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Event {
    ServerInfo(ServerInfo),
    Packet {
        source: PublicKey<Node>,
        payload: Vec<u8>,
    },
    KeepAlive,
    Ping([u8; 8]),
    Pong([u8; 8]),
    PeerGone {
        peer: PublicKey<Node>,
        reason: u8,
    },
    Health(String),
    Restarting {
        reconnect_in_ms: u32,
        try_for_ms: u32,
    },
}

#[derive(Serialize)]
struct ClientInfo {
    #[serde(rename = "version")]
    version: u8,
    #[serde(rename = "CanAckPings")]
    can_ack_pings: bool,
}

pub struct DerpClient<S> {
    io: BufReader<S>,
    private_key: PrivateKey<Node>,
    server_key: PublicKey<Node>,
}

impl<S: Read + Write> DerpClient<S> {
    pub fn connect(
        mut stream: S,
        authority: &str,
        private_key: PrivateKey<Node>,
    ) -> Result<Self, DerpError> {
        validate_authority(authority)?;
        write!(
            stream,
            "GET /derp HTTP/1.1\r\nHost: {authority}\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n"
        )?;
        stream.flush()?;

        let mut io = BufReader::new(stream);
        read_upgrade_response(&mut io)?;
        let (kind, greeting) = read_frame(&mut io)?;
        if kind != FRAME_SERVER_KEY || greeting.len() < 40 || &greeting[..8] != MAGIC {
            return Err(DerpError::InvalidServerGreeting);
        }
        let server_key = PublicKey::<Node>::from_bytes(
            greeting[8..40].try_into().expect("greeting length checked"),
        );
        let client_info = serde_json::to_vec(&ClientInfo {
            version: PROTOCOL_VERSION,
            can_ack_pings: true,
        })?;
        let sealed = seal(&private_key, server_key, &client_info)?;
        let mut payload = Vec::with_capacity(32 + sealed.len());
        payload.extend_from_slice(private_key.public().as_bytes());
        payload.extend_from_slice(&sealed);
        write_frame(io.get_mut(), FRAME_CLIENT_INFO, &payload)?;

        Ok(Self {
            io,
            private_key,
            server_key,
        })
    }

    pub fn server_key(&self) -> PublicKey<Node> {
        self.server_key
    }

    pub fn send(&mut self, destination: PublicKey<Node>, packet: &[u8]) -> Result<(), DerpError> {
        if packet.len() > MAX_PACKET_SIZE {
            return Err(DerpError::PacketTooLarge(packet.len()));
        }
        let mut payload = Vec::with_capacity(32 + packet.len());
        payload.extend_from_slice(destination.as_bytes());
        payload.extend_from_slice(packet);
        write_frame(self.io.get_mut(), FRAME_SEND_PACKET, &payload)
    }

    pub fn note_preferred(&mut self, preferred: bool) -> Result<(), DerpError> {
        write_frame(
            self.io.get_mut(),
            FRAME_NOTE_PREFERRED,
            &[u8::from(preferred)],
        )
    }

    pub fn send_ping(&mut self, payload: [u8; 8]) -> Result<(), DerpError> {
        write_frame(self.io.get_mut(), FRAME_PING, &payload)
    }

    pub fn receive(&mut self) -> Result<Event, DerpError> {
        loop {
            let (kind, payload) = read_frame(&mut self.io)?;
            match kind {
                FRAME_SERVER_INFO => {
                    let plaintext = open(&self.private_key, self.server_key, payload.as_slice())?;
                    return Ok(Event::ServerInfo(serde_json::from_slice(&plaintext)?));
                }
                FRAME_RECV_PACKET if payload.len() >= 32 => {
                    let source = PublicKey::<Node>::from_bytes(
                        payload[..32].try_into().expect("packet length checked"),
                    );
                    return Ok(Event::Packet {
                        source,
                        payload: payload[32..].to_vec(),
                    });
                }
                FRAME_KEEP_ALIVE => return Ok(Event::KeepAlive),
                FRAME_PING if payload.len() >= 8 => {
                    let ping: [u8; 8] = payload[..8].try_into().expect("ping length checked");
                    write_frame(self.io.get_mut(), FRAME_PONG, &ping)?;
                    return Ok(Event::Ping(ping));
                }
                FRAME_PONG if payload.len() >= 8 => {
                    return Ok(Event::Pong(
                        payload[..8].try_into().expect("pong length checked"),
                    ));
                }
                FRAME_PEER_GONE if payload.len() >= 32 => {
                    let peer = PublicKey::<Node>::from_bytes(
                        payload[..32].try_into().expect("peer key length checked"),
                    );
                    return Ok(Event::PeerGone {
                        peer,
                        reason: payload.get(32).copied().unwrap_or(0),
                    });
                }
                FRAME_HEALTH => {
                    return String::from_utf8(payload)
                        .map(Event::Health)
                        .map_err(|_| DerpError::InvalidHealthMessage);
                }
                FRAME_RESTARTING if payload.len() >= 8 => {
                    return Ok(Event::Restarting {
                        reconnect_in_ms: u32::from_be_bytes(
                            payload[..4].try_into().expect("restart length checked"),
                        ),
                        try_for_ms: u32::from_be_bytes(
                            payload[4..8].try_into().expect("restart length checked"),
                        ),
                    });
                }
                _ => continue,
            }
        }
    }

    pub fn into_inner(self) -> S {
        self.io.into_inner()
    }
}

fn validate_authority(authority: &str) -> Result<(), DerpError> {
    if authority.is_empty()
        || !authority.is_ascii()
        || authority
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(DerpError::InvalidAuthority);
    }
    Ok(())
}

fn read_upgrade_response<S: Read>(reader: &mut BufReader<S>) -> Result<(), DerpError> {
    let mut total = 0;
    let mut line = Vec::new();
    reader.read_until(b'\n', &mut line)?;
    total += line.len();
    let status = std::str::from_utf8(&line)
        .map_err(|_| DerpError::InvalidHttpResponse)?
        .split_ascii_whitespace()
        .nth(1)
        .ok_or(DerpError::InvalidHttpResponse)?;
    if status != "101" {
        return Err(DerpError::UpgradeRejected(status.to_owned()));
    }
    loop {
        line.clear();
        reader.read_until(b'\n', &mut line)?;
        total += line.len();
        if total > MAX_HTTP_HEADERS {
            return Err(DerpError::HttpHeadersTooLarge);
        }
        if line == b"\r\n" || line == b"\n" {
            return Ok(());
        }
        if line.is_empty() {
            return Err(DerpError::InvalidHttpResponse);
        }
    }
}

fn read_frame<R: Read>(reader: &mut R) -> Result<(u8, Vec<u8>), DerpError> {
    let mut header = [0_u8; 5];
    reader.read_exact(&mut header)?;
    let length = u32::from_be_bytes(header[1..].try_into().expect("fixed frame header")) as usize;
    if length > MAX_FRAME_SIZE {
        return Err(DerpError::FrameTooLarge(length));
    }
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload)?;
    Ok((header[0], payload))
}

fn write_frame<W: Write>(writer: &mut W, kind: u8, payload: &[u8]) -> Result<(), DerpError> {
    let length =
        u32::try_from(payload.len()).map_err(|_| DerpError::FrameTooLarge(payload.len()))?;
    writer.write_all(&[kind])?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(payload)?;
    writer.flush()?;
    Ok(())
}

fn seal(
    private_key: &PrivateKey<Node>,
    remote_key: PublicKey<Node>,
    plaintext: &[u8],
) -> Result<Vec<u8>, DerpError> {
    let mut nonce = [0_u8; 24];
    getrandom::getrandom(&mut nonce).map_err(|_| DerpError::Random)?;
    let cipher = SalsaBox::new(
        &BoxPublicKey::from(*remote_key.as_bytes()),
        &BoxSecretKey::from(*private_key.as_bytes()),
    );
    let encrypted = cipher
        .encrypt(
            crypto_box::aead::generic_array::GenericArray::from_slice(&nonce),
            plaintext,
        )
        .map_err(|_| DerpError::Authentication)?;
    let mut message = Vec::with_capacity(nonce.len() + encrypted.len());
    message.extend_from_slice(&nonce);
    message.extend_from_slice(&encrypted);
    Ok(message)
}

fn open(
    private_key: &PrivateKey<Node>,
    remote_key: PublicKey<Node>,
    message: &[u8],
) -> Result<Vec<u8>, DerpError> {
    if message.len() < 24 + 16 {
        return Err(DerpError::Authentication);
    }
    let cipher = SalsaBox::new(
        &BoxPublicKey::from(*remote_key.as_bytes()),
        &BoxSecretKey::from(*private_key.as_bytes()),
    );
    cipher
        .decrypt(
            crypto_box::aead::generic_array::GenericArray::from_slice(&message[..24]),
            &message[24..],
        )
        .map_err(|_| DerpError::Authentication)
}

#[derive(Debug, Error)]
pub enum DerpError {
    #[error("DERP I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("DERP JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid DERP server authority")]
    InvalidAuthority,
    #[error("invalid DERP HTTP upgrade response")]
    InvalidHttpResponse,
    #[error("DERP HTTP upgrade was rejected with status {0}")]
    UpgradeRejected(String),
    #[error("DERP HTTP response headers exceed the size limit")]
    HttpHeadersTooLarge,
    #[error("invalid DERP server greeting")]
    InvalidServerGreeting,
    #[error("DERP frame is too large: {0} bytes")]
    FrameTooLarge(usize),
    #[error("DERP packet is too large: {0} bytes")]
    PacketTooLarge(usize),
    #[error("DERP authenticated encryption failed")]
    Authentication,
    #[error("DERP random generation failed")]
    Random,
    #[error("DERP health message is not valid UTF-8")]
    InvalidHealthMessage,
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Write};

    use super::{open, seal, DerpClient, DerpError, Event, FRAME_PONG, FRAME_SERVER_INFO, MAGIC};
    use crate::key::{Node, PrivateKey};

    struct Duplex {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl Read for Duplex {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(buffer)
        }
    }

    impl Write for Duplex {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.output.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![kind];
        bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    fn connected_input(client: &PrivateKey<Node>, server: &PrivateKey<Node>) -> Vec<u8> {
        let mut bytes = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\n\r\n".to_vec();
        let mut greeting = MAGIC.to_vec();
        greeting.extend_from_slice(server.public().as_bytes());
        bytes.extend_from_slice(&frame(1, &greeting));
        let info = seal(server, client.public(), br#"{"version":2}"#).unwrap();
        bytes.extend_from_slice(&frame(FRAME_SERVER_INFO, &info));
        bytes.extend_from_slice(&frame(0x12, b"12345678"));
        bytes
    }

    #[test]
    fn upgrades_authenticates_and_acks_server_pings() {
        let client_key = PrivateKey::<Node>::from_bytes([1; 32]);
        let server_key = PrivateKey::<Node>::from_bytes([2; 32]);
        let io = Duplex {
            input: Cursor::new(connected_input(&client_key, &server_key)),
            output: Vec::new(),
        };
        let mut client = DerpClient::connect(io, "derp.example.com", client_key.clone()).unwrap();
        assert_eq!(client.server_key(), server_key.public());
        assert_eq!(
            client.receive().unwrap(),
            Event::ServerInfo(super::ServerInfo {
                version: 2,
                token_bucket_bytes_per_second: 0,
                token_bucket_bytes_burst: 0,
            })
        );
        assert_eq!(client.receive().unwrap(), Event::Ping(*b"12345678"));

        let io = client.into_inner();
        assert!(io.output.starts_with(b"GET /derp HTTP/1.1\r\n"));
        let pong = frame(FRAME_PONG, b"12345678");
        assert!(io.output.ends_with(&pong));

        let request_end = io
            .output
            .windows(4)
            .position(|part| part == b"\r\n\r\n")
            .unwrap()
            + 4;
        let client_info = &io.output[request_end..];
        assert_eq!(client_info[0], 2);
        let payload_len = u32::from_be_bytes(client_info[1..5].try_into().unwrap()) as usize;
        let payload = &client_info[5..5 + payload_len];
        assert_eq!(&payload[..32], client_key.public().as_bytes());
        let clear = open(&server_key, client_key.public(), &payload[32..]).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&clear).unwrap();
        assert_eq!(value["version"], 2);
        assert_eq!(value["CanAckPings"], true);
    }

    #[test]
    fn rejects_header_injection_and_oversized_packets() {
        let key = PrivateKey::<Node>::from_bytes([1; 32]);
        let io = Duplex {
            input: Cursor::new(Vec::new()),
            output: Vec::new(),
        };
        assert!(matches!(
            DerpClient::connect(io, "bad\r\nhost", key.clone()),
            Err(DerpError::InvalidAuthority)
        ));

        let server = PrivateKey::<Node>::from_bytes([2; 32]);
        let io = Duplex {
            input: Cursor::new(connected_input(&key, &server)),
            output: Vec::new(),
        };
        let mut client = DerpClient::connect(io, "derp.example.com", key).unwrap();
        assert!(matches!(
            client.send(server.public(), &[0; super::MAX_PACKET_SIZE + 1]),
            Err(DerpError::PacketTooLarge(_))
        ));
    }
}
