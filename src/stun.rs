use std::net::{Ipv4Addr, SocketAddrV4};

use thiserror::Error;

const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const MAGIC_COOKIE: u32 = 0x2112_a442;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;
const SOFTWARE: u16 = 0x8022;
const FINGERPRINT: u16 = 0x8028;
const SOFTWARE_VALUE: &[u8; 8] = b"tailnode";

pub fn binding_request(transaction_id: [u8; 12]) -> [u8; 40] {
    let mut request = [0_u8; 40];
    request[..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    request[2..4].copy_from_slice(&20_u16.to_be_bytes());
    request[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    request[8..20].copy_from_slice(&transaction_id);
    request[20..22].copy_from_slice(&SOFTWARE.to_be_bytes());
    request[22..24].copy_from_slice(&(SOFTWARE_VALUE.len() as u16).to_be_bytes());
    request[24..32].copy_from_slice(SOFTWARE_VALUE);
    request[32..34].copy_from_slice(&FINGERPRINT.to_be_bytes());
    request[34..36].copy_from_slice(&4_u16.to_be_bytes());
    let fingerprint = crc32(&request[..32]) ^ 0x5354_554e;
    request[36..].copy_from_slice(&fingerprint.to_be_bytes());
    request
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= *byte as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0_u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

pub fn parse_binding_response(
    packet: &[u8],
    transaction_id: [u8; 12],
) -> Result<SocketAddrV4, StunError> {
    if packet.len() < 20
        || u16::from_be_bytes([packet[0], packet[1]]) != BINDING_SUCCESS
        || u32::from_be_bytes(packet[4..8].try_into().expect("fixed-length slice")) != MAGIC_COOKIE
        || packet[8..20] != transaction_id
    {
        return Err(StunError::InvalidResponse);
    }
    let payload_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if payload_len > packet.len() - 20 {
        return Err(StunError::Truncated);
    }
    let cookie = MAGIC_COOKIE.to_be_bytes();
    let mut attributes = &packet[20..20 + payload_len];
    while attributes.len() >= 4 {
        let kind = u16::from_be_bytes([attributes[0], attributes[1]]);
        let length = u16::from_be_bytes([attributes[2], attributes[3]]) as usize;
        if attributes.len() < 4 + length {
            return Err(StunError::Truncated);
        }
        let value = &attributes[4..4 + length];
        if matches!(kind, XOR_MAPPED_ADDRESS | 0x8020) {
            if value.len() < 4 {
                return Err(StunError::Truncated);
            }
            let port = u16::from_be_bytes([value[2], value[3]]) ^ (MAGIC_COOKIE >> 16) as u16;
            let address = match (value[1], value.len()) {
                (1, 8) => Ipv4Addr::new(
                    value[4] ^ cookie[0],
                    value[5] ^ cookie[1],
                    value[6] ^ cookie[2],
                    value[7] ^ cookie[3],
                ),
                (2, 20) => {
                    let mut decoded = [0_u8; 16];
                    for index in 0..16 {
                        let mask = if index < 4 {
                            cookie[index]
                        } else {
                            transaction_id[index - 4]
                        };
                        decoded[index] = value[4 + index] ^ mask;
                    }
                    std::net::Ipv6Addr::from(decoded)
                        .to_ipv4_mapped()
                        .ok_or(StunError::UnsupportedAddress)?
                }
                _ => return Err(StunError::UnsupportedAddress),
            };
            return Ok(SocketAddrV4::new(address, port));
        }
        let padded = (length + 3) & !3;
        if attributes.len() < 4 + padded {
            return Err(StunError::Truncated);
        }
        attributes = &attributes[4 + padded..];
    }
    Err(StunError::MissingMappedAddress)
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum StunError {
    #[error("invalid STUN binding response")]
    InvalidResponse,
    #[error("truncated STUN binding response")]
    Truncated,
    #[error("STUN response contains an unsupported mapped address")]
    UnsupportedAddress,
    #[error("STUN response does not contain a mapped address")]
    MissingMappedAddress,
}

#[cfg(test)]
mod tests {
    use super::{binding_request, parse_binding_response, MAGIC_COOKIE};

    #[test]
    fn creates_request_and_parses_xor_mapped_ipv4() {
        let transaction_id = [0x42; 12];
        let request = binding_request(transaction_id);
        assert_eq!(&request[..2], &[0, 1]);
        assert_eq!(&request[8..20], &transaction_id);
        assert_eq!(&request[24..32], b"tailnode");

        let mut response = Vec::new();
        response.extend_from_slice(&0x0101_u16.to_be_bytes());
        response.extend_from_slice(&12_u16.to_be_bytes());
        response.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        response.extend_from_slice(&transaction_id);
        response.extend_from_slice(&0x0020_u16.to_be_bytes());
        response.extend_from_slice(&8_u16.to_be_bytes());
        response.extend_from_slice(&[0, 1]);
        response.extend_from_slice(&(45678_u16 ^ 0x2112).to_be_bytes());
        let cookie = MAGIC_COOKIE.to_be_bytes();
        for (address, mask) in [203_u8, 0, 113, 9].into_iter().zip(cookie) {
            response.push(address ^ mask);
        }
        assert_eq!(
            parse_binding_response(&response, transaction_id)
                .unwrap()
                .to_string(),
            "203.0.113.9:45678"
        );
    }
}
