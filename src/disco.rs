use std::net::{IpAddr, SocketAddr};

use crypto_box::aead::{Aead, AeadCore, OsRng};
use crypto_box::{PublicKey as BoxPublicKey, SalsaBox, SecretKey as BoxSecretKey};
use thiserror::Error;

use super::key::{Disco, Node, PrivateKey, PublicKey};

const MAGIC: &[u8; 6] = b"TS\xf0\x9f\x92\xac";
const HEADER_LEN: usize = 6 + 32 + 24;
const PING: u8 = 1;
const PONG: u8 = 2;

#[derive(Debug, Eq, PartialEq)]
pub struct Ping {
    pub sender_disco_key: PublicKey<Disco>,
    pub transaction_id: [u8; 12],
    pub node_key: Option<PublicKey<Node>>,
}

pub fn open_ping(local_private: &PrivateKey<Disco>, packet: &[u8]) -> Result<Ping, DiscoError> {
    if packet.len() < HEADER_LEN + 16 + 14 || !packet.starts_with(MAGIC) {
        return Err(DiscoError::InvalidPacket);
    }
    let sender_bytes: [u8; 32] = packet[6..38].try_into().expect("fixed-length slice");
    let sender_disco_key = PublicKey::<Disco>::from_bytes(sender_bytes);
    let nonce = crypto_box::aead::generic_array::GenericArray::from_slice(&packet[38..62]);
    let cipher = SalsaBox::new(
        &BoxPublicKey::from(sender_bytes),
        &BoxSecretKey::from(*local_private.as_bytes()),
    );
    let plaintext = cipher
        .decrypt(nonce, &packet[62..])
        .map_err(|_| DiscoError::Authentication)?;
    if plaintext.len() < 14 || plaintext[0] != PING || plaintext[1] != 0 {
        return Err(DiscoError::NotPing);
    }
    let transaction_id = plaintext[2..14].try_into().expect("fixed-length slice");
    let node_key = (plaintext.len() >= 46).then(|| {
        PublicKey::<Node>::from_bytes(plaintext[14..46].try_into().expect("fixed-length slice"))
    });
    Ok(Ping {
        sender_disco_key,
        transaction_id,
        node_key,
    })
}

pub fn seal_pong(
    local_private: &PrivateKey<Disco>,
    remote_public: PublicKey<Disco>,
    transaction_id: [u8; 12],
    observed_source: SocketAddr,
) -> Result<Vec<u8>, DiscoError> {
    let mut plaintext = Vec::with_capacity(32);
    plaintext.extend_from_slice(&[PONG, 0]);
    plaintext.extend_from_slice(&transaction_id);
    plaintext.extend_from_slice(&ip_as_16(observed_source.ip()));
    plaintext.extend_from_slice(&observed_source.port().to_be_bytes());

    let cipher = SalsaBox::new(
        &BoxPublicKey::from(*remote_public.as_bytes()),
        &BoxSecretKey::from(*local_private.as_bytes()),
    );
    let nonce = SalsaBox::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_slice())
        .map_err(|_| DiscoError::Authentication)?;
    let mut packet = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    packet.extend_from_slice(MAGIC);
    packet.extend_from_slice(local_private.public().as_bytes());
    packet.extend_from_slice(&nonce);
    packet.extend_from_slice(&ciphertext);
    Ok(packet)
}

fn ip_as_16(address: IpAddr) -> [u8; 16] {
    match address {
        IpAddr::V4(address) => address.to_ipv6_mapped().octets(),
        IpAddr::V6(address) => address.octets(),
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum DiscoError {
    #[error("invalid Tailscale discovery packet")]
    InvalidPacket,
    #[error("Tailscale discovery packet authentication failed")]
    Authentication,
    #[error("Tailscale discovery packet is not a supported ping")]
    NotPing,
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use crypto_box::aead::{Aead, AeadCore, OsRng};
    use crypto_box::{PublicKey as BoxPublicKey, SalsaBox, SecretKey as BoxSecretKey};

    use super::{open_ping, seal_pong, HEADER_LEN, MAGIC};
    use crate::key::{Disco, Node, PrivateKey};

    #[test]
    fn opens_ping_and_returns_authenticated_pong() {
        let sender = PrivateKey::<Disco>::from_bytes([0x11; 32]);
        let receiver = PrivateKey::<Disco>::from_bytes([0x22; 32]);
        let sender_node = PrivateKey::<Node>::from_bytes([0x33; 32]);
        let transaction_id = [0x44; 12];
        let mut ping = vec![1, 0];
        ping.extend_from_slice(&transaction_id);
        ping.extend_from_slice(sender_node.public().as_bytes());

        let cipher = SalsaBox::new(
            &BoxPublicKey::from(*receiver.public().as_bytes()),
            &BoxSecretKey::from(*sender.as_bytes()),
        );
        let nonce = SalsaBox::generate_nonce(&mut OsRng);
        let encrypted = cipher.encrypt(&nonce, ping.as_slice()).unwrap();
        let mut packet = MAGIC.to_vec();
        packet.extend_from_slice(sender.public().as_bytes());
        packet.extend_from_slice(&nonce);
        packet.extend_from_slice(&encrypted);

        let parsed = open_ping(&receiver, &packet).unwrap();
        assert_eq!(parsed.transaction_id, transaction_id);
        assert_eq!(parsed.node_key, Some(sender_node.public()));

        let observed = "192.0.2.10:45678".parse::<SocketAddr>().unwrap();
        let pong = seal_pong(
            &receiver,
            parsed.sender_disco_key,
            parsed.transaction_id,
            observed,
        )
        .unwrap();
        assert!(pong.starts_with(MAGIC));
        assert!(pong.len() > HEADER_LEN);
        let nonce = crypto_box::aead::generic_array::GenericArray::<
            u8,
            <SalsaBox as AeadCore>::NonceSize,
        >::from_slice(&pong[38..62]);
        let cipher = SalsaBox::new(
            &BoxPublicKey::from(*receiver.public().as_bytes()),
            &BoxSecretKey::from(*sender.as_bytes()),
        );
        let clear = cipher.decrypt(nonce, &pong[62..]).unwrap();
        assert_eq!(
            &clear[..14],
            &[2, 0].into_iter().chain(transaction_id).collect::<Vec<_>>()
        );
        assert_eq!(&clear[26..30], &[192, 0, 2, 10]);
        assert_eq!(u16::from_be_bytes(clear[30..32].try_into().unwrap()), 45678);
    }
}
