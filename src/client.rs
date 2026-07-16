use std::collections::VecDeque;
use std::io::{Read, Write};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::h2::{
    Frame, H2Error, HeaderCodec, Response, ResponseAssembler, StreamEvent, StreamResponseAssembler,
    CLIENT_PREFACE,
};
use super::key::{Challenge, Machine, PrivateKey, PublicKey};
use super::noise::{NoiseError, NoiseInitiator, NoiseTransport, MAX_PLAINTEXT_LEN};

const MAX_HTTP_HEADERS: usize = 16 * 1024;
const MAX_EARLY_NOISE: usize = 64 * 1024;
const MAX_RESPONSE_FRAMES: usize = 4096;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct EarlyNoise {
    #[serde(rename = "nodeKeyChallenge")]
    pub node_key_challenge: PublicKey<Challenge>,
}

pub struct ControlConnection<S> {
    stream: S,
    transport: NoiseTransport,
    pending: VecDeque<u8>,
    headers: HeaderCodec,
    next_stream_id: u32,
    early_noise: EarlyNoise,
    authority: String,
}

pub struct ControlStream {
    stream_id: u32,
    assembler: StreamResponseAssembler,
    ended: bool,
}

impl<S: Read + Write> ControlConnection<S> {
    pub fn upgrade(
        mut stream: S,
        authority: impl Into<String>,
        machine_key: &PrivateKey<Machine>,
        control_key: PublicKey<Machine>,
        capability_version: u16,
    ) -> Result<Self, ControlClientError> {
        let authority = authority.into();
        let mut initiator = NoiseInitiator::new(machine_key, control_key, capability_version)?;
        let initiation = initiator.initiation()?;
        let request = format!(
            "POST /ts2021 HTTP/1.1\r\n\
             Host: {authority}\r\n\
             Connection: upgrade\r\n\
             Upgrade: tailscale-control-protocol\r\n\
             X-Tailscale-Handshake: {}\r\n\
             Content-Length: 0\r\n\
             \r\n",
            STANDARD.encode(initiation)
        );
        stream.write_all(request.as_bytes())?;

        let response_headers = read_http_headers(&mut stream)?;
        let response_headers = String::from_utf8(response_headers)?;
        if !response_headers.starts_with("HTTP/1.1 101 ") {
            return Err(ControlClientError::UpgradeRejected(
                response_headers
                    .lines()
                    .next()
                    .unwrap_or("empty HTTP response")
                    .to_owned(),
            ));
        }
        if !response_headers
            .to_ascii_lowercase()
            .contains("upgrade: tailscale-control-protocol")
        {
            return Err(ControlClientError::WrongUpgradeProtocol);
        }

        let mut response = [0_u8; 51];
        stream.read_exact(&mut response)?;
        let mut transport = initiator.finish(&response)?;
        let mut pending = VecDeque::new();

        let mut early_header = [0_u8; 9];
        read_plain_exact(&mut stream, &mut transport, &mut pending, &mut early_header)?;
        if &early_header[..5] != b"\xff\xff\xffTS" {
            return Err(ControlClientError::InvalidEarlyNoise);
        }
        let early_len = u32::from_be_bytes(
            early_header[5..]
                .try_into()
                .expect("EarlyNoise header has a fixed size"),
        ) as usize;
        if early_len > MAX_EARLY_NOISE {
            return Err(ControlClientError::EarlyNoiseTooLarge(early_len));
        }
        let mut early_payload = vec![0_u8; early_len];
        read_plain_exact(
            &mut stream,
            &mut transport,
            &mut pending,
            &mut early_payload,
        )?;
        let early_noise = serde_json::from_slice(&early_payload)?;

        let mut connection = Self {
            stream,
            transport,
            pending,
            headers: HeaderCodec::default(),
            next_stream_id: 1,
            early_noise,
            authority,
        };
        let mut h2_start = CLIENT_PREFACE.to_vec();
        h2_start.extend_from_slice(&Frame::settings().encode()?);
        h2_start.extend_from_slice(&Frame::connection_window_update().encode()?);
        connection.write_plain(&h2_start)?;
        let settings = connection.read_h2_frame()?;
        if !settings.is_settings() {
            return Err(ControlClientError::ExpectedSettings);
        }
        connection.write_h2_frame(Frame::settings_ack())?;
        Ok(connection)
    }

    pub fn early_noise(&self) -> &EarlyNoise {
        &self.early_noise
    }

    pub fn post_json<T: Serialize>(
        &mut self,
        path: &str,
        body: &T,
        load_balance_keys: &[&str],
        max_response_len: usize,
    ) -> Result<Response, ControlClientError> {
        let body = serde_json::to_vec(body)?;
        let headers: Vec<_> = load_balance_keys
            .iter()
            .map(|key| ("ts-lb", *key))
            .collect();
        self.request("POST", path, &body, &headers, max_response_len)
    }

    pub fn post_json_decode<T: Serialize, R: DeserializeOwned>(
        &mut self,
        path: &str,
        body: &T,
        load_balance_keys: &[&str],
        max_response_len: usize,
    ) -> Result<R, ControlClientError> {
        let response = self.post_json(path, body, load_balance_keys, max_response_len)?;
        if response.status != 200 {
            return Err(ControlClientError::HttpStatus {
                status: response.status,
                body: String::from_utf8_lossy(&response.body)
                    .chars()
                    .take(200)
                    .collect(),
            });
        }
        Ok(serde_json::from_slice(&response.body)?)
    }

    pub fn request(
        &mut self,
        method: &str,
        path: &str,
        body: &[u8],
        extra_headers: &[(&str, &str)],
        max_response_len: usize,
    ) -> Result<Response, ControlClientError> {
        let stream_id = self.next_stream_id;
        self.next_stream_id = self
            .next_stream_id
            .checked_add(2)
            .filter(|id| *id <= 0x7fff_ffff)
            .ok_or(ControlClientError::StreamIdsExhausted)?;
        let frames = self.headers.request(
            stream_id,
            method,
            path,
            &self.authority,
            body,
            extra_headers,
        )?;
        for frame in frames {
            self.write_h2_frame(frame)?;
        }

        let mut assembler = ResponseAssembler::new(stream_id, max_response_len)?;
        for _ in 0..MAX_RESPONSE_FRAMES {
            let frame = self.read_h2_frame()?;
            if frame.is_settings() {
                self.write_h2_frame(Frame::settings_ack())?;
                continue;
            }
            if frame.is_ping_request() {
                self.write_h2_frame(Frame::ping_ack(frame.payload)?)?;
                continue;
            }
            if frame.is_connection_error() {
                return Err(ControlClientError::ConnectionClosed);
            }
            if frame.is_stream_error(stream_id) {
                return Err(ControlClientError::StreamReset(stream_id));
            }
            if let Some(response) = assembler.push(frame, &mut self.headers)? {
                return Ok(response);
            }
        }
        Err(ControlClientError::TooManyResponseFrames)
    }

    pub fn start_json_stream<T: Serialize>(
        &mut self,
        path: &str,
        body: &T,
        load_balance_keys: &[&str],
    ) -> Result<ControlStream, ControlClientError> {
        let body = serde_json::to_vec(body)?;
        let headers: Vec<_> = load_balance_keys
            .iter()
            .map(|key| ("ts-lb", *key))
            .collect();
        let stream_id = self.allocate_stream_id()?;
        let frames =
            self.headers
                .request(stream_id, "POST", path, &self.authority, &body, &headers)?;
        for frame in frames {
            self.write_h2_frame(frame)?;
        }
        Ok(ControlStream {
            stream_id,
            assembler: StreamResponseAssembler::new(stream_id)?,
            ended: false,
        })
    }

    pub fn read_stream_event(
        &mut self,
        stream: &mut ControlStream,
    ) -> Result<StreamEvent, ControlClientError> {
        if stream.ended {
            return Err(ControlClientError::StreamEnded(stream.stream_id));
        }
        loop {
            let frame = self.read_h2_frame()?;
            if frame.is_settings() {
                self.write_h2_frame(Frame::settings_ack())?;
                continue;
            }
            if frame.is_ping_request() {
                self.write_h2_frame(Frame::ping_ack(frame.payload)?)?;
                continue;
            }
            if frame.is_connection_error() {
                return Err(ControlClientError::ConnectionClosed);
            }
            if frame.is_stream_error(stream.stream_id) {
                return Err(ControlClientError::StreamReset(stream.stream_id));
            }
            let data_len = if frame.kind == 0 && frame.stream_id == stream.stream_id {
                u32::try_from(frame.payload.len()).unwrap_or(u32::MAX)
            } else {
                0
            };
            let Some(event) = stream.assembler.push(frame, &mut self.headers)? else {
                continue;
            };
            if data_len > 0 {
                self.write_h2_frame(Frame::window_update(0, data_len)?)?;
                self.write_h2_frame(Frame::window_update(stream.stream_id, data_len)?)?;
            }
            stream.ended = match &event {
                StreamEvent::Headers { end_stream, .. } | StreamEvent::Data { end_stream, .. } => {
                    *end_stream
                }
            };
            return Ok(event);
        }
    }

    fn allocate_stream_id(&mut self) -> Result<u32, ControlClientError> {
        let stream_id = self.next_stream_id;
        self.next_stream_id = self
            .next_stream_id
            .checked_add(2)
            .filter(|id| *id <= 0x7fff_ffff)
            .ok_or(ControlClientError::StreamIdsExhausted)?;
        Ok(stream_id)
    }

    fn write_h2_frame(&mut self, frame: Frame) -> Result<(), ControlClientError> {
        self.write_plain(&frame.encode()?)
    }

    fn write_plain(&mut self, plaintext: &[u8]) -> Result<(), ControlClientError> {
        for chunk in plaintext.chunks(MAX_PLAINTEXT_LEN) {
            self.stream.write_all(&self.transport.encrypt(chunk)?)?;
        }
        Ok(())
    }

    fn read_h2_frame(&mut self) -> Result<Frame, ControlClientError> {
        let mut header = [0_u8; 9];
        read_plain_exact(
            &mut self.stream,
            &mut self.transport,
            &mut self.pending,
            &mut header,
        )?;
        let payload_len =
            ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | header[2] as usize;
        if payload_len > 1 << 20 {
            return Err(ControlClientError::H2(H2Error::FrameTooLarge(payload_len)));
        }
        let mut encoded = Vec::with_capacity(9 + payload_len);
        encoded.extend_from_slice(&header);
        encoded.resize(9 + payload_len, 0);
        read_plain_exact(
            &mut self.stream,
            &mut self.transport,
            &mut self.pending,
            &mut encoded[9..],
        )?;
        Frame::parse(&encoded)?
            .map(|(frame, _)| frame)
            .ok_or(ControlClientError::IncompleteH2Frame)
    }
}

fn read_plain_exact<S: Read>(
    stream: &mut S,
    transport: &mut NoiseTransport,
    pending: &mut VecDeque<u8>,
    output: &mut [u8],
) -> Result<(), ControlClientError> {
    let mut offset = 0;
    while offset < output.len() {
        while offset < output.len() {
            let Some(byte) = pending.pop_front() else {
                break;
            };
            output[offset] = byte;
            offset += 1;
        }
        if offset == output.len() {
            break;
        }

        let mut header = [0_u8; 3];
        stream.read_exact(&mut header)?;
        let payload_len = u16::from_be_bytes([header[1], header[2]]) as usize;
        if payload_len > 4093 {
            return Err(ControlClientError::NoiseFrameTooLarge(payload_len));
        }
        let mut frame = vec![0_u8; payload_len + 3];
        frame[..3].copy_from_slice(&header);
        stream.read_exact(&mut frame[3..])?;
        pending.extend(transport.decrypt(&frame)?);
    }
    Ok(())
}

fn read_http_headers<S: Read>(stream: &mut S) -> Result<Vec<u8>, ControlClientError> {
    let mut headers = Vec::with_capacity(512);
    let mut byte = [0_u8; 1];
    while headers.len() < MAX_HTTP_HEADERS {
        stream.read_exact(&mut byte)?;
        headers.push(byte[0]);
        if headers.ends_with(b"\r\n\r\n") {
            return Ok(headers);
        }
    }
    Err(ControlClientError::HttpHeadersTooLarge)
}

#[derive(Debug, Error)]
pub enum ControlClientError {
    #[error("control I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("control Noise failed: {0}")]
    Noise(#[from] NoiseError),
    #[error("control HTTP/2 failed: {0}")]
    H2(#[from] H2Error),
    #[error("control JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("control HTTP headers are not UTF-8: {0}")]
    HeaderUtf8(#[from] std::string::FromUtf8Error),
    #[error("control rejected protocol upgrade: {0}")]
    UpgradeRejected(String),
    #[error("control selected an unexpected upgrade protocol")]
    WrongUpgradeProtocol,
    #[error("control HTTP response headers exceeded the size limit")]
    HttpHeadersTooLarge,
    #[error("control sent an invalid EarlyNoise header")]
    InvalidEarlyNoise,
    #[error("control EarlyNoise payload is too large: {0} bytes")]
    EarlyNoiseTooLarge(usize),
    #[error("expected initial HTTP/2 SETTINGS")]
    ExpectedSettings,
    #[error("incomplete HTTP/2 frame")]
    IncompleteH2Frame,
    #[error("control Noise frame is too large: {0} bytes")]
    NoiseFrameTooLarge(usize),
    #[error("HTTP/2 stream IDs exhausted")]
    StreamIdsExhausted,
    #[error("control closed the HTTP/2 connection")]
    ConnectionClosed,
    #[error("control reset HTTP/2 stream {0}")]
    StreamReset(u32),
    #[error("control HTTP/2 stream {0} has already ended")]
    StreamEnded(u32),
    #[error("control response exceeded the frame count limit")]
    TooManyResponseFrames,
    #[error("control returned HTTP {status}: {body}")]
    HttpStatus { status: u16, body: String },
}
