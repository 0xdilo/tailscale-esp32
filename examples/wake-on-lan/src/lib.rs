use hmac::{Hmac, Mac};
use sha2::Sha256;

pub const DASHBOARD_HTML: &str = include_str!("dashboard.html");
pub const MAGIC_PACKET_LEN: usize = 102;
pub const MAX_CLOCK_SKEW_SECONDS: u64 = 90;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Eq, PartialEq)]
pub enum AuthError {
    InvalidTimestamp,
    Expired,
    InvalidNonce,
    InvalidSignature,
}

pub fn parse_mac(value: &str) -> Result<[u8; 6], &'static str> {
    let mut mac = [0_u8; 6];
    let mut parts = value.split(':');

    for byte in &mut mac {
        let part = parts.next().ok_or("MAC address has fewer than six bytes")?;
        if part.len() != 2 {
            return Err("each MAC address byte must contain two hex digits");
        }
        *byte = u8::from_str_radix(part, 16).map_err(|_| "MAC address contains invalid hex")?;
    }

    if parts.next().is_some() {
        return Err("MAC address has more than six bytes");
    }

    Ok(mac)
}

pub fn magic_packet(mac: [u8; 6]) -> [u8; MAGIC_PACKET_LEN] {
    let mut packet = [0_u8; MAGIC_PACKET_LEN];
    packet[..6].fill(0xff);

    for chunk in packet[6..].chunks_exact_mut(6) {
        chunk.copy_from_slice(&mac);
    }

    packet
}

pub fn wake_signature(secret: &[u8], path: &str, timestamp: u64, nonce: &str) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts keys of any length");
    mac.update(canonical_request(path, timestamp, nonce).as_bytes());
    mac.finalize().into_bytes().into()
}

pub fn verify_wake_request(
    secret: &[u8],
    path: &str,
    timestamp_text: &str,
    nonce: &str,
    signature: &str,
    now: u64,
) -> Result<(), AuthError> {
    let timestamp = timestamp_text
        .parse::<u64>()
        .map_err(|_| AuthError::InvalidTimestamp)?;
    if timestamp.abs_diff(now) > MAX_CLOCK_SKEW_SECONDS {
        return Err(AuthError::Expired);
    }
    if nonce.len() != 32 || !nonce.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AuthError::InvalidNonce);
    }

    let signature = decode_signature(signature)?;
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts keys of any length");
    mac.update(canonical_request(path, timestamp, nonce).as_bytes());
    mac.verify_slice(&signature)
        .map_err(|_| AuthError::InvalidSignature)
}

fn canonical_request(path: &str, timestamp: u64, nonce: &str) -> String {
    format!("esp32wake-v1\n{timestamp}\n{nonce}\nPOST\n{path}")
}

fn decode_signature(value: &str) -> Result<[u8; 32], AuthError> {
    if value.len() != 64 {
        return Err(AuthError::InvalidSignature);
    }

    let mut decoded = [0_u8; 32];
    for (output, pair) in decoded.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let pair = std::str::from_utf8(pair).map_err(|_| AuthError::InvalidSignature)?;
        *output = u8::from_str_radix(pair, 16).map_err(|_| AuthError::InvalidSignature)?;
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::{
        magic_packet, parse_mac, verify_wake_request, wake_signature, AuthError, DASHBOARD_HTML,
        MAGIC_PACKET_LEN,
    };

    const SECRET: &[u8] = b"a-long-test-secret-that-is-not-production";
    const PATH: &str = "/wake-71f00d";
    const NONCE: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn parses_mac_case_insensitively() {
        assert_eq!(
            parse_mac("84:9E:56:b2:7c:97"),
            Ok([0x84, 0x9e, 0x56, 0xb2, 0x7c, 0x97])
        );
    }

    #[test]
    fn rejects_malformed_mac() {
        assert!(parse_mac("00:11:22:33:44").is_err());
        assert!(parse_mac("00:11:22:33:44:55:66").is_err());
        assert!(parse_mac("00:11:22:33:44:zz").is_err());
    }

    #[test]
    fn creates_standard_magic_packet() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let packet = magic_packet(mac);

        assert_eq!(packet.len(), MAGIC_PACKET_LEN);
        assert_eq!(&packet[..6], &[0xff; 6]);
        assert!(packet[6..].chunks_exact(6).all(|chunk| chunk == mac));
    }

    #[test]
    fn embeds_a_self_contained_dashboard() {
        assert!(DASHBOARD_HTML.starts_with("<!doctype html>"));
        assert!(DASHBOARD_HTML.contains("tailscale-esp32"));
        assert!(DASHBOARD_HTML.contains("href=\"/health\""));
        assert!(!DASHBOARD_HTML.contains("<script"));
        assert!(!DASHBOARD_HTML.contains("https://"));
    }

    #[test]
    fn verifies_a_current_signed_request() {
        let signature = encode_hex(wake_signature(SECRET, PATH, 1_700_000_000, NONCE));
        assert_eq!(
            verify_wake_request(SECRET, PATH, "1700000000", NONCE, &signature, 1_700_000_030),
            Ok(())
        );
    }

    #[test]
    fn rejects_tampering_and_stale_requests() {
        let signature = encode_hex(wake_signature(SECRET, PATH, 1_700_000_000, NONCE));
        assert_eq!(
            verify_wake_request(
                SECRET,
                "/different",
                "1700000000",
                NONCE,
                &signature,
                1_700_000_000
            ),
            Err(AuthError::InvalidSignature)
        );
        assert_eq!(
            verify_wake_request(SECRET, PATH, "1700000000", NONCE, &signature, 1_700_000_091),
            Err(AuthError::Expired)
        );
    }

    #[test]
    fn rejects_invalid_nonce_and_signature_encodings() {
        assert_eq!(
            verify_wake_request(SECRET, PATH, "1700000000", "not-hex", "00", 1_700_000_000),
            Err(AuthError::InvalidNonce)
        );
        assert_eq!(
            verify_wake_request(
                SECRET,
                PATH,
                "1700000000",
                NONCE,
                "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
                1_700_000_000
            ),
            Err(AuthError::InvalidSignature)
        );
    }

    fn encode_hex(value: [u8; 32]) -> String {
        value.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
