use std::net::{IpAddr, SocketAddr};

use crypto_box::aead::Aead;
use crypto_box::{PublicKey as BoxPublicKey, SalsaBox, SecretKey as BoxSecretKey};
use thiserror::Error;

use super::key::{Disco, Node, PrivateKey, PublicKey};

const MAGIC: &[u8; 6] = b"TS\xf0\x9f\x92\xac";
const HEADER_LEN: usize = 6 + 32 + 24;
const PING: u8 = 1;
const PONG: u8 = 2;
const CALL_ME_MAYBE: u8 = 3;

#[derive(Debug, Eq, PartialEq)]
pub struct Ping {
    pub sender_disco_key: PublicKey<Disco>,
    pub transaction_id: [u8; 12],
    pub node_key: Option<PublicKey<Node>>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Pong {
    pub sender_disco_key: PublicKey<Disco>,
    pub transaction_id: [u8; 12],
    pub observed_source: SocketAddr,
}

#[derive(Debug, Eq, PartialEq)]
pub struct CallMeMaybe {
    pub sender_disco_key: PublicKey<Disco>,
    pub endpoints: Vec<SocketAddr>,
}

pub fn open_ping(local_private: &PrivateKey<Disco>, packet: &[u8]) -> Result<Ping, DiscoError> {
    let (sender_disco_key, plaintext) = open_wrapper(local_private, packet)?;
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

pub fn seal_ping(
    local_private: &PrivateKey<Disco>,
    remote_public: PublicKey<Disco>,
    transaction_id: [u8; 12],
    node_key: PublicKey<Node>,
) -> Result<Vec<u8>, DiscoError> {
    let mut plaintext = Vec::with_capacity(46);
    plaintext.extend_from_slice(&[PING, 0]);
    plaintext.extend_from_slice(&transaction_id);
    plaintext.extend_from_slice(node_key.as_bytes());
    seal_wrapper(local_private, remote_public, &plaintext)
}

pub fn open_pong(local_private: &PrivateKey<Disco>, packet: &[u8]) -> Result<Pong, DiscoError> {
    let (sender_disco_key, plaintext) = open_wrapper(local_private, packet)?;
    if plaintext.len() < 32 || plaintext[0] != PONG || plaintext[1] != 0 {
        return Err(DiscoError::NotPong);
    }
    let transaction_id = plaintext[2..14].try_into().expect("fixed-length slice");
    let ip: [u8; 16] = plaintext[14..30].try_into().expect("fixed-length slice");
    let port = u16::from_be_bytes(plaintext[30..32].try_into().expect("fixed-length slice"));
    Ok(Pong {
        sender_disco_key,
        transaction_id,
        observed_source: SocketAddr::new(IpAddr::from(ip).to_canonical(), port),
    })
}

pub fn seal_call_me_maybe(
    local_private: &PrivateKey<Disco>,
    remote_public: PublicKey<Disco>,
    endpoints: &[SocketAddr],
) -> Result<Vec<u8>, DiscoError> {
    if endpoints.is_empty() || endpoints.len() > u16::MAX as usize {
        return Err(DiscoError::InvalidEndpoints);
    }
    let mut plaintext = Vec::with_capacity(2 + endpoints.len() * 18);
    plaintext.extend_from_slice(&[CALL_ME_MAYBE, 0]);
    for endpoint in endpoints {
        plaintext.extend_from_slice(&ip_as_16(endpoint.ip()));
        plaintext.extend_from_slice(&endpoint.port().to_be_bytes());
    }
    seal_wrapper(local_private, remote_public, &plaintext)
}

pub fn open_call_me_maybe(
    local_private: &PrivateKey<Disco>,
    packet: &[u8],
) -> Result<CallMeMaybe, DiscoError> {
    let (sender_disco_key, plaintext) = open_wrapper(local_private, packet)?;
    if plaintext.len() <= 2
        || plaintext[0] != CALL_ME_MAYBE
        || plaintext[1] != 0
        || (plaintext.len() - 2) % 18 != 0
    {
        return Err(DiscoError::NotCallMeMaybe);
    }
    let endpoints = plaintext[2..]
        .chunks_exact(18)
        .map(|endpoint| {
            let ip = IpAddr::from(<[u8; 16]>::try_from(&endpoint[..16]).expect("fixed chunk"));
            let port = u16::from_be_bytes(endpoint[16..18].try_into().expect("fixed chunk"));
            SocketAddr::new(ip.to_canonical(), port)
        })
        .collect();
    Ok(CallMeMaybe {
        sender_disco_key,
        endpoints,
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

    seal_wrapper(local_private, remote_public, &plaintext)
}

fn open_wrapper(
    local_private: &PrivateKey<Disco>,
    packet: &[u8],
) -> Result<(PublicKey<Disco>, Vec<u8>), DiscoError> {
    if packet.len() < HEADER_LEN + 16 + 2 || !packet.starts_with(MAGIC) {
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
    Ok((sender_disco_key, plaintext))
}

fn seal_wrapper(
    local_private: &PrivateKey<Disco>,
    remote_public: PublicKey<Disco>,
    plaintext: &[u8],
) -> Result<Vec<u8>, DiscoError> {
    let cipher = SalsaBox::new(
        &BoxPublicKey::from(*remote_public.as_bytes()),
        &BoxSecretKey::from(*local_private.as_bytes()),
    );
    let mut nonce = [0_u8; 24];
    getrandom::getrandom(&mut nonce).map_err(|_| DiscoError::Random)?;
    let ciphertext = cipher
        .encrypt(
            crypto_box::aead::generic_array::GenericArray::from_slice(&nonce),
            plaintext,
        )
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
    #[error("Tailscale discovery packet is not a supported pong")]
    NotPong,
    #[error("Tailscale discovery packet is not a CallMeMaybe message")]
    NotCallMeMaybe,
    #[error("Tailscale discovery endpoints are invalid")]
    InvalidEndpoints,
    #[error("random generation for Tailscale discovery failed")]
    Random,
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use crypto_box::aead::{Aead, AeadCore};
    use crypto_box::{PublicKey as BoxPublicKey, SalsaBox, SecretKey as BoxSecretKey};

    use super::{
        open_call_me_maybe, open_ping, open_pong, seal_call_me_maybe, seal_ping, seal_pong,
        HEADER_LEN, MAGIC,
    };
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
        let nonce = [0x55; 24];
        let encrypted = cipher
            .encrypt(
                crypto_box::aead::generic_array::GenericArray::from_slice(&nonce),
                ping.as_slice(),
            )
            .unwrap();
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

    #[test]
    fn exchanges_ping_pong_and_call_me_maybe_messages() {
        let sender = PrivateKey::<Disco>::from_bytes([0x11; 32]);
        let receiver = PrivateKey::<Disco>::from_bytes([0x22; 32]);
        let node = PrivateKey::<Node>::from_bytes([0x33; 32]);
        let transaction_id = [0x44; 12];

        let ping = seal_ping(&sender, receiver.public(), transaction_id, node.public()).unwrap();
        let opened = open_ping(&receiver, &ping).unwrap();
        assert_eq!(opened.transaction_id, transaction_id);
        assert_eq!(opened.node_key, Some(node.public()));

        let source = "[2001:db8::1]:41641".parse().unwrap();
        let pong = seal_pong(&receiver, sender.public(), transaction_id, source).unwrap();
        let opened = open_pong(&sender, &pong).unwrap();
        assert_eq!(opened.transaction_id, transaction_id);
        assert_eq!(opened.observed_source, source);

        let endpoints = [
            "192.0.2.1:41641".parse().unwrap(),
            "[2001:db8::2]:41641".parse().unwrap(),
        ];
        let message = seal_call_me_maybe(&sender, receiver.public(), &endpoints).unwrap();
        let opened = open_call_me_maybe(&receiver, &message).unwrap();
        assert_eq!(opened.sender_disco_key, sender.public());
        assert_eq!(opened.endpoints, endpoints);
    }
}
