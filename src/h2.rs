use httlib_hpack::{Decoder, Encoder};
use thiserror::Error;

pub const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const DATA: u8 = 0;
const HEADERS: u8 = 1;
const SETTINGS: u8 = 4;
const CONTINUATION: u8 = 9;
const END_STREAM: u8 = 1;
const ACK: u8 = 1;
const END_HEADERS: u8 = 4;
const PADDED: u8 = 8;
const PRIORITY: u8 = 32;
const MAX_FRAME_PAYLOAD: usize = 16_384;
const MAX_RECEIVED_FRAME_PAYLOAD: usize = 1 << 20;
const RECEIVE_WINDOW: u32 = 1 << 20;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub kind: u8,
    pub flags: u8,
    pub stream_id: u32,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn settings() -> Self {
        let mut payload = Vec::with_capacity(6);
        payload.extend_from_slice(&4_u16.to_be_bytes());
        payload.extend_from_slice(&RECEIVE_WINDOW.to_be_bytes());
        Self::new(SETTINGS, 0, 0, payload)
    }

    pub fn settings_ack() -> Self {
        Self::new(SETTINGS, ACK, 0, Vec::new())
    }

    pub fn connection_window_update() -> Self {
        let increment = RECEIVE_WINDOW - 65_535;
        Self::new(8, 0, 0, increment.to_be_bytes().to_vec())
    }

    pub fn window_update(stream_id: u32, increment: u32) -> Result<Self, H2Error> {
        if increment == 0 || increment > 0x7fff_ffff {
            return Err(H2Error::InvalidWindowIncrement(increment));
        }
        Ok(Self::new(8, 0, stream_id, increment.to_be_bytes().to_vec()))
    }

    pub fn ping_ack(payload: Vec<u8>) -> Result<Self, H2Error> {
        if payload.len() != 8 {
            return Err(H2Error::InvalidPing);
        }
        Ok(Self::new(6, ACK, 0, payload))
    }

    pub fn new(kind: u8, flags: u8, stream_id: u32, payload: Vec<u8>) -> Self {
        Self {
            kind,
            flags,
            stream_id,
            payload,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, H2Error> {
        if self.payload.len() > 0x00ff_ffff {
            return Err(H2Error::FrameTooLarge(self.payload.len()));
        }
        if self.stream_id > 0x7fff_ffff {
            return Err(H2Error::InvalidStreamId(self.stream_id));
        }
        let length = self.payload.len() as u32;
        let mut encoded = Vec::with_capacity(9 + self.payload.len());
        encoded.extend_from_slice(&length.to_be_bytes()[1..]);
        encoded.push(self.kind);
        encoded.push(self.flags);
        encoded.extend_from_slice(&self.stream_id.to_be_bytes());
        encoded.extend_from_slice(&self.payload);
        Ok(encoded)
    }

    pub fn parse(bytes: &[u8]) -> Result<Option<(Self, usize)>, H2Error> {
        if bytes.len() < 9 {
            return Ok(None);
        }
        let length = ((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize;
        if length > MAX_RECEIVED_FRAME_PAYLOAD {
            return Err(H2Error::FrameTooLarge(length));
        }
        let total = 9 + length;
        if bytes.len() < total {
            return Ok(None);
        }
        let raw_stream_id = u32::from_be_bytes(bytes[5..9].try_into().expect("fixed length"));
        Ok(Some((
            Self {
                kind: bytes[3],
                flags: bytes[4],
                stream_id: raw_stream_id & 0x7fff_ffff,
                payload: bytes[9..total].to_vec(),
            },
            total,
        )))
    }

    pub fn is_settings(&self) -> bool {
        self.kind == SETTINGS && self.stream_id == 0 && self.flags & ACK == 0
    }

    pub fn is_ping_request(&self) -> bool {
        self.kind == 6 && self.stream_id == 0 && self.flags & ACK == 0
    }

    pub fn is_connection_error(&self) -> bool {
        self.kind == 7
    }

    pub fn is_stream_error(&self, stream_id: u32) -> bool {
        self.kind == 3 && self.stream_id == stream_id
    }
}

#[derive(Default)]
pub struct HeaderCodec {
    encoder: Encoder<'static>,
    decoder: Decoder<'static>,
}

impl HeaderCodec {
    pub fn request(
        &mut self,
        stream_id: u32,
        method: &str,
        path: &str,
        authority: &str,
        body: &[u8],
        extra_headers: &[(&str, &str)],
    ) -> Result<Vec<Frame>, H2Error> {
        if stream_id == 0 || stream_id & 1 == 0 {
            return Err(H2Error::InvalidStreamId(stream_id));
        }

        let content_length = body.len().to_string();
        let mut headers = vec![
            (":method", method),
            (":scheme", "https"),
            (":authority", authority),
            (":path", path),
            ("content-type", "application/json"),
            ("content-length", content_length.as_str()),
        ];
        headers.extend_from_slice(extra_headers);

        let mut block = Vec::new();
        let flags = Encoder::BEST_FORMAT | Encoder::NEVER_INDEXED;
        for (name, value) in headers {
            self.encoder.encode(
                (name.as_bytes().to_vec(), value.as_bytes().to_vec(), flags),
                &mut block,
            )?;
        }
        if block.len() > MAX_FRAME_PAYLOAD {
            return Err(H2Error::HeaderBlockTooLarge(block.len()));
        }

        let header_flags = END_HEADERS | if body.is_empty() { END_STREAM } else { 0 };
        let mut frames = vec![Frame::new(HEADERS, header_flags, stream_id, block)];
        if !body.is_empty() {
            let chunk_count = body.len().div_ceil(MAX_FRAME_PAYLOAD);
            for (index, chunk) in body.chunks(MAX_FRAME_PAYLOAD).enumerate() {
                let flags = if index + 1 == chunk_count {
                    END_STREAM
                } else {
                    0
                };
                frames.push(Frame::new(DATA, flags, stream_id, chunk.to_vec()));
            }
        }
        Ok(frames)
    }

    fn decode(&mut self, mut block: Vec<u8>) -> Result<Vec<(String, String)>, H2Error> {
        let mut decoded = Vec::new();
        self.decoder.decode(&mut block, &mut decoded)?;
        decoded
            .into_iter()
            .map(|(name, value, _)| Ok((String::from_utf8(name)?, String::from_utf8(value)?)))
            .collect()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

pub struct ResponseAssembler {
    stream_id: u32,
    header_block: Vec<u8>,
    headers: Option<Vec<(String, String)>>,
    body: Vec<u8>,
    expecting_continuation: bool,
    max_body_len: usize,
}

#[derive(Debug, Eq, PartialEq)]
pub enum StreamEvent {
    Headers {
        status: u16,
        headers: Vec<(String, String)>,
        end_stream: bool,
    },
    Data {
        payload: Vec<u8>,
        end_stream: bool,
    },
}

pub struct StreamResponseAssembler {
    stream_id: u32,
    header_block: Vec<u8>,
    headers_received: bool,
    expecting_continuation: bool,
    headers_end_stream: bool,
}

impl StreamResponseAssembler {
    pub fn new(stream_id: u32) -> Result<Self, H2Error> {
        if stream_id == 0 {
            return Err(H2Error::InvalidStreamId(stream_id));
        }
        Ok(Self {
            stream_id,
            header_block: Vec::new(),
            headers_received: false,
            expecting_continuation: false,
            headers_end_stream: false,
        })
    }

    pub fn push(
        &mut self,
        frame: Frame,
        codec: &mut HeaderCodec,
    ) -> Result<Option<StreamEvent>, H2Error> {
        if frame.stream_id != self.stream_id {
            return Ok(None);
        }
        if self.expecting_continuation && frame.kind != CONTINUATION {
            return Err(H2Error::ExpectedContinuation);
        }
        match frame.kind {
            HEADERS => {
                if self.headers_received || self.expecting_continuation {
                    return Err(H2Error::UnexpectedHeaders);
                }
                self.header_block
                    .extend_from_slice(headers_fragment(&frame)?);
                self.expecting_continuation = frame.flags & END_HEADERS == 0;
                self.headers_end_stream = frame.flags & END_STREAM != 0;
                if self.expecting_continuation {
                    Ok(None)
                } else {
                    self.finish_headers(codec).map(Some)
                }
            }
            CONTINUATION => {
                if !self.expecting_continuation {
                    return Err(H2Error::ExpectedHeaders);
                }
                self.header_block.extend_from_slice(&frame.payload);
                self.expecting_continuation = frame.flags & END_HEADERS == 0;
                if self.expecting_continuation {
                    Ok(None)
                } else {
                    self.finish_headers(codec).map(Some)
                }
            }
            DATA => {
                if !self.headers_received || self.expecting_continuation {
                    return Err(H2Error::ExpectedHeaders);
                }
                Ok(Some(StreamEvent::Data {
                    payload: data_fragment(&frame)?.to_vec(),
                    end_stream: frame.flags & END_STREAM != 0,
                }))
            }
            _ => Ok(None),
        }
    }

    fn finish_headers(&mut self, codec: &mut HeaderCodec) -> Result<StreamEvent, H2Error> {
        let headers = codec.decode(std::mem::take(&mut self.header_block))?;
        let status = headers
            .iter()
            .find(|(name, _)| name == ":status")
            .ok_or(H2Error::MissingStatus)?
            .1
            .parse()
            .map_err(|_| H2Error::InvalidStatus)?;
        self.headers_received = true;
        Ok(StreamEvent::Headers {
            status,
            headers,
            end_stream: self.headers_end_stream,
        })
    }
}

impl ResponseAssembler {
    pub fn new(stream_id: u32, max_body_len: usize) -> Result<Self, H2Error> {
        if stream_id == 0 {
            return Err(H2Error::InvalidStreamId(stream_id));
        }
        Ok(Self {
            stream_id,
            header_block: Vec::new(),
            headers: None,
            body: Vec::new(),
            expecting_continuation: false,
            max_body_len,
        })
    }

    pub fn push(
        &mut self,
        frame: Frame,
        codec: &mut HeaderCodec,
    ) -> Result<Option<Response>, H2Error> {
        if frame.stream_id != self.stream_id {
            return Ok(None);
        }
        if self.expecting_continuation && frame.kind != CONTINUATION {
            return Err(H2Error::ExpectedContinuation);
        }

        match frame.kind {
            HEADERS => {
                if self.headers.is_some() || self.expecting_continuation {
                    return Err(H2Error::UnexpectedHeaders);
                }
                self.header_block
                    .extend_from_slice(headers_fragment(&frame)?);
                self.expecting_continuation = frame.flags & END_HEADERS == 0;
                if !self.expecting_continuation {
                    self.headers = Some(codec.decode(std::mem::take(&mut self.header_block))?);
                }
            }
            CONTINUATION => {
                if !self.expecting_continuation {
                    return Err(H2Error::ExpectedHeaders);
                }
                self.header_block.extend_from_slice(&frame.payload);
                self.expecting_continuation = frame.flags & END_HEADERS == 0;
                if !self.expecting_continuation {
                    self.headers = Some(codec.decode(std::mem::take(&mut self.header_block))?);
                }
            }
            DATA => {
                if self.headers.is_none() || self.expecting_continuation {
                    return Err(H2Error::ExpectedHeaders);
                }
                let payload = data_fragment(&frame)?;
                if self.body.len() + payload.len() > self.max_body_len {
                    return Err(H2Error::BodyTooLarge(self.body.len() + payload.len()));
                }
                self.body.extend_from_slice(payload);
            }
            _ => return Ok(None),
        }

        if frame.flags & END_STREAM == 0 {
            return Ok(None);
        }
        let headers = self.headers.take().ok_or(H2Error::ExpectedHeaders)?;
        let status = headers
            .iter()
            .find(|(name, _)| name == ":status")
            .ok_or(H2Error::MissingStatus)?
            .1
            .parse()
            .map_err(|_| H2Error::InvalidStatus)?;
        Ok(Some(Response {
            status,
            headers,
            body: std::mem::take(&mut self.body),
        }))
    }
}

fn headers_fragment(frame: &Frame) -> Result<&[u8], H2Error> {
    let mut start = 0;
    let mut end = frame.payload.len();
    if frame.flags & PADDED != 0 {
        let padding = *frame.payload.first().ok_or(H2Error::InvalidPadding)? as usize;
        start = 1;
        end = end.checked_sub(padding).ok_or(H2Error::InvalidPadding)?;
        if start > end {
            return Err(H2Error::InvalidPadding);
        }
    }
    if frame.flags & PRIORITY != 0 {
        start = start.checked_add(5).ok_or(H2Error::InvalidPriority)?;
        if start > end {
            return Err(H2Error::InvalidPriority);
        }
    }
    Ok(&frame.payload[start..end])
}

fn data_fragment(frame: &Frame) -> Result<&[u8], H2Error> {
    if frame.flags & PADDED == 0 {
        return Ok(&frame.payload);
    }
    let padding = *frame.payload.first().ok_or(H2Error::InvalidPadding)? as usize;
    let end = frame
        .payload
        .len()
        .checked_sub(padding)
        .ok_or(H2Error::InvalidPadding)?;
    if end < 1 {
        return Err(H2Error::InvalidPadding);
    }
    Ok(&frame.payload[1..end])
}

#[derive(Debug, Error)]
pub enum H2Error {
    #[error("HTTP/2 frame payload is too large: {0} bytes")]
    FrameTooLarge(usize),
    #[error("invalid HTTP/2 stream ID {0}")]
    InvalidStreamId(u32),
    #[error("HTTP/2 header block is too large: {0} bytes")]
    HeaderBlockTooLarge(usize),
    #[error("HPACK encoding failed: {0}")]
    HeaderEncode(#[from] httlib_hpack::EncoderError),
    #[error("HPACK decoding failed: {0}")]
    HeaderDecode(#[from] httlib_hpack::DecoderError),
    #[error("HTTP/2 header text is not UTF-8: {0}")]
    HeaderUtf8(#[from] std::string::FromUtf8Error),
    #[error("expected an HTTP/2 HEADERS frame")]
    ExpectedHeaders,
    #[error("expected an HTTP/2 CONTINUATION frame")]
    ExpectedContinuation,
    #[error("received duplicate HTTP/2 HEADERS")]
    UnexpectedHeaders,
    #[error("invalid HTTP/2 frame padding")]
    InvalidPadding,
    #[error("invalid HTTP/2 priority section")]
    InvalidPriority,
    #[error("HTTP/2 response is missing :status")]
    MissingStatus,
    #[error("HTTP/2 response has an invalid :status")]
    InvalidStatus,
    #[error("HTTP/2 response body is too large: {0} bytes")]
    BodyTooLarge(usize),
    #[error("HTTP/2 PING payload must be exactly eight bytes")]
    InvalidPing,
    #[error("invalid HTTP/2 window increment {0}")]
    InvalidWindowIncrement(u32),
}

#[cfg(test)]
mod tests {
    use httlib_hpack::Encoder;

    use super::{
        Frame, HeaderCodec, ResponseAssembler, StreamEvent, StreamResponseAssembler, DATA,
        END_HEADERS, END_STREAM, HEADERS,
    };

    #[test]
    fn frame_round_trips() {
        let frame = Frame::new(DATA, END_STREAM, 3, b"hello".to_vec());
        let encoded = frame.encode().unwrap();
        let (decoded, consumed) = Frame::parse(&encoded).unwrap().unwrap();
        assert_eq!(decoded, frame);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn request_encodes_headers_and_chunked_body() {
        let mut codec = HeaderCodec::default();
        let body = vec![42_u8; 20_000];
        let frames = codec
            .request(1, "POST", "/machine/map", "control.example", &body, &[])
            .unwrap();
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].kind, HEADERS);
        assert_eq!(frames[1].payload.len(), 16_384);
        assert_eq!(frames[2].flags, END_STREAM);
    }

    #[test]
    fn assembles_hpack_response() {
        let mut encoder = HeaderCodec::default();
        let encoded = encoder
            .request(1, "GET", "/", "control.example", &[], &[])
            .unwrap();
        let request_block = encoded[0].payload.clone();
        let mut decoder = HeaderCodec::default();
        let headers = decoder.decode(request_block).unwrap();
        assert!(headers.contains(&(":method".into(), "GET".into())));

        let mut block = Vec::new();
        let flags = Encoder::BEST_FORMAT;
        encoder
            .encoder
            .encode((b":status".to_vec(), b"200".to_vec(), flags), &mut block)
            .unwrap();
        let mut assembler = ResponseAssembler::new(1, 1024).unwrap();
        assert!(assembler
            .push(Frame::new(HEADERS, END_HEADERS, 1, block), &mut decoder)
            .unwrap()
            .is_none());
        let response = assembler
            .push(
                Frame::new(DATA, END_STREAM, 1, b"ok".to_vec()),
                &mut decoder,
            )
            .unwrap()
            .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"ok");
    }

    #[test]
    fn streams_headers_and_data_without_buffering_the_body() {
        let mut encoder = HeaderCodec::default();
        let mut block = Vec::new();
        encoder
            .encoder
            .encode(
                (b":status".to_vec(), b"200".to_vec(), Encoder::BEST_FORMAT),
                &mut block,
            )
            .unwrap();
        let mut decoder = HeaderCodec::default();
        let mut assembler = StreamResponseAssembler::new(1).unwrap();
        assert!(matches!(
            assembler
                .push(Frame::new(HEADERS, END_HEADERS, 1, block), &mut decoder)
                .unwrap(),
            Some(StreamEvent::Headers {
                status: 200,
                end_stream: false,
                ..
            })
        ));
        assert_eq!(
            assembler
                .push(Frame::new(DATA, 0, 1, b"first".to_vec()), &mut decoder)
                .unwrap(),
            Some(StreamEvent::Data {
                payload: b"first".to_vec(),
                end_stream: false,
            })
        );
        assert_eq!(
            assembler
                .push(
                    Frame::new(DATA, END_STREAM, 1, b"last".to_vec()),
                    &mut decoder,
                )
                .unwrap(),
            Some(StreamEvent::Data {
                payload: b"last".to_vec(),
                end_stream: true,
            })
        );
    }

    #[test]
    fn validates_window_updates() {
        assert_eq!(
            Frame::window_update(3, 1024).unwrap().payload,
            1024_u32.to_be_bytes()
        );
        assert!(Frame::window_update(0, 0).is_err());
        assert!(Frame::window_update(0, 0x8000_0000).is_err());
    }
}
