use std::cmp::Ordering;
use std::fmt;
use std::marker::PhantomData;

use ed25519_dalek::{Signer, SigningKey};
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub trait KeyKind: Copy {
    const PUBLIC_PREFIX: &'static str;
}

pub trait CurveKeyKind: KeyKind {}

#[derive(Clone, Copy, Debug)]
pub enum Machine {}

#[derive(Clone, Copy, Debug)]
pub enum Node {}

#[derive(Clone, Copy, Debug)]
pub enum Disco {}

#[derive(Clone, Copy, Debug)]
pub enum Challenge {}

#[derive(Clone, Copy, Debug)]
pub enum NetworkLock {}

impl KeyKind for Machine {
    const PUBLIC_PREFIX: &'static str = "mkey:";
}

impl KeyKind for Node {
    const PUBLIC_PREFIX: &'static str = "nodekey:";
}

impl KeyKind for Disco {
    const PUBLIC_PREFIX: &'static str = "discokey:";
}

impl KeyKind for Challenge {
    const PUBLIC_PREFIX: &'static str = "chalpub:";
}

impl KeyKind for NetworkLock {
    const PUBLIC_PREFIX: &'static str = "nlpub:";
}

impl CurveKeyKind for Machine {}
impl CurveKeyKind for Node {}
impl CurveKeyKind for Disco {}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey<K: CurveKeyKind> {
    bytes: [u8; 32],
    #[zeroize(skip)]
    kind: PhantomData<K>,
}

impl<K: CurveKeyKind> PrivateKey<K> {
    pub fn from_bytes(mut bytes: [u8; 32]) -> Self {
        bytes[0] &= 248;
        bytes[31] &= 127;
        bytes[31] |= 64;
        Self {
            bytes,
            kind: PhantomData,
        }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    pub fn public(&self) -> PublicKey<K> {
        PublicKey::from_bytes(x25519(self.bytes, X25519_BASEPOINT_BYTES))
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct NetworkLockPrivateKey {
    seed: [u8; 32],
}

impl NetworkLockPrivateKey {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self { seed }
    }

    pub fn public(&self) -> PublicKey<NetworkLock> {
        let signing_key = SigningKey::from_bytes(&self.seed);
        PublicKey::from_bytes(signing_key.verifying_key().to_bytes())
    }

    pub fn as_seed(&self) -> &[u8; 32] {
        &self.seed
    }

    pub(crate) fn sign(&self, message: &[u8]) -> [u8; 64] {
        SigningKey::from_bytes(&self.seed).sign(message).to_bytes()
    }
}

pub struct PublicKey<K: KeyKind> {
    bytes: [u8; 32],
    kind: PhantomData<K>,
}

impl<K: KeyKind> PublicKey<K> {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            bytes,
            kind: PhantomData,
        }
    }

    pub const fn zero() -> Self {
        Self::from_bytes([0; 32])
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    pub fn parse(value: &str) -> Result<Self, KeyParseError> {
        let encoded = value
            .strip_prefix(K::PUBLIC_PREFIX)
            .ok_or(KeyParseError::WrongPrefix)?;
        if encoded.len() != 64 {
            return Err(KeyParseError::WrongLength);
        }

        let mut bytes = [0_u8; 32];
        for (output, pair) in bytes.iter_mut().zip(encoded.as_bytes().chunks_exact(2)) {
            let pair = std::str::from_utf8(pair).map_err(|_| KeyParseError::InvalidHex)?;
            *output = u8::from_str_radix(pair, 16).map_err(|_| KeyParseError::InvalidHex)?;
        }
        Ok(Self::from_bytes(bytes))
    }
}

impl<K: KeyKind> Clone for PublicKey<K> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<K: KeyKind> Copy for PublicKey<K> {}

impl<K: KeyKind> PartialEq for PublicKey<K> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<K: KeyKind> Eq for PublicKey<K> {}

impl<K: KeyKind> PartialOrd for PublicKey<K> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<K: KeyKind> Ord for PublicKey<K> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.bytes.cmp(&other.bytes)
    }
}

impl<K: KeyKind> Default for PublicKey<K> {
    fn default() -> Self {
        Self::zero()
    }
}

impl<K: KeyKind> fmt::Debug for PublicKey<K> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(K::PUBLIC_PREFIX)?;
        write_hex(formatter, &self.bytes[..4])?;
        formatter.write_str("…")
    }
}

impl<K: KeyKind> fmt::Display for PublicKey<K> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(K::PUBLIC_PREFIX)?;
        write_hex(formatter, &self.bytes)
    }
}

impl<K: KeyKind> Serialize for PublicKey<K> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de, K: KeyKind> Deserialize<'de> for PublicKey<K> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(D::Error::custom)
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum KeyParseError {
    #[error("key has the wrong type prefix")]
    WrongPrefix,
    #[error("key must contain exactly 32 bytes")]
    WrongLength,
    #[error("key contains invalid hexadecimal data")]
    InvalidHex,
}

fn write_hex(formatter: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        Challenge, Disco, Machine, NetworkLock, NetworkLockPrivateKey, Node, PrivateKey, PublicKey,
    };

    #[test]
    fn serializes_each_public_key_with_its_wire_prefix() {
        let bytes = [0xab; 32];
        assert!(PublicKey::<Machine>::from_bytes(bytes)
            .to_string()
            .starts_with("mkey:"));
        assert!(PublicKey::<Node>::from_bytes(bytes)
            .to_string()
            .starts_with("nodekey:"));
        assert!(PublicKey::<Disco>::from_bytes(bytes)
            .to_string()
            .starts_with("discokey:"));
        assert!(PublicKey::<Challenge>::from_bytes(bytes)
            .to_string()
            .starts_with("chalpub:"));
        assert!(PublicKey::<NetworkLock>::from_bytes(bytes)
            .to_string()
            .starts_with("nlpub:"));
    }

    #[test]
    fn public_key_json_round_trips() {
        let key = PublicKey::<Machine>::from_bytes([0x42; 32]);
        let json = serde_json::to_string(&key).unwrap();
        assert_eq!(
            serde_json::from_str::<PublicKey<Machine>>(&json).unwrap(),
            key
        );
    }

    #[test]
    fn clamps_private_keys_like_tailscale() {
        let key = PrivateKey::<Machine>::from_bytes([0xff; 32]);
        assert_eq!(key.as_bytes()[0] & 7, 0);
        assert_eq!(key.as_bytes()[31] & 0x80, 0);
        assert_ne!(key.as_bytes()[31] & 0x40, 0);
        assert_ne!(key.public().as_bytes(), &[0; 32]);
    }

    #[test]
    fn derives_tailnet_lock_ed25519_public_key() {
        let private = NetworkLockPrivateKey::from_seed([0x55; 32]);
        assert_ne!(private.public().as_bytes(), &[0; 32]);
        assert!(private.public().to_string().starts_with("nlpub:"));
    }
}
