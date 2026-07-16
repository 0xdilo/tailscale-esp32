use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::key::{Disco, Machine, NetworkLockPrivateKey, Node, PrivateKey};

const FORMAT_VERSION: u8 = 1;
const KEY_LEN: usize = 32;
const KEY_COUNT: usize = 5;

/// Encoded length of a persistent [`DeviceIdentity`].
pub const ENCODED_IDENTITY_LEN: usize = 1 + KEY_LEN * KEY_COUNT;

/// Persistent private identity used by a constrained Tailscale node.
///
/// Store the encoded value in a device-protected persistent store. Recreating
/// it registers a new machine and invalidates continuity with the old node.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DeviceIdentity {
    machine: PrivateKey<Machine>,
    node: PrivateKey<Node>,
    disco: PrivateKey<Disco>,
    network_lock: NetworkLockPrivateKey,
    backend_log_id: [u8; KEY_LEN],
}

impl DeviceIdentity {
    /// Generates a new identity from the platform cryptographic RNG.
    pub fn generate() -> Result<Self, IdentityError> {
        let mut random = [0_u8; KEY_LEN * KEY_COUNT];
        getrandom::getrandom(&mut random)?;
        Ok(Self::from_key_material(random))
    }

    /// Decodes an identity previously returned by [`Self::encode`].
    pub fn decode(encoded: &[u8]) -> Result<Self, IdentityError> {
        if encoded.len() != ENCODED_IDENTITY_LEN {
            return Err(IdentityError::InvalidLength(encoded.len()));
        }
        if encoded[0] != FORMAT_VERSION {
            return Err(IdentityError::UnsupportedVersion(encoded[0]));
        }
        let material = encoded[1..]
            .try_into()
            .expect("identity length validated before conversion");
        Ok(Self::from_key_material(material))
    }

    /// Encodes the identity for persistent storage.
    pub fn encode(&self) -> [u8; ENCODED_IDENTITY_LEN] {
        let mut encoded = [0_u8; ENCODED_IDENTITY_LEN];
        encoded[0] = FORMAT_VERSION;
        for (slot, key) in encoded[1..].chunks_exact_mut(KEY_LEN).zip([
            self.machine.as_bytes(),
            self.node.as_bytes(),
            self.disco.as_bytes(),
            self.network_lock.as_seed(),
            &self.backend_log_id,
        ]) {
            slot.copy_from_slice(key);
        }
        encoded
    }

    pub fn machine_key(&self) -> &PrivateKey<Machine> {
        &self.machine
    }

    pub fn node_key(&self) -> &PrivateKey<Node> {
        &self.node
    }

    pub fn disco_key(&self) -> &PrivateKey<Disco> {
        &self.disco
    }

    pub fn network_lock_key(&self) -> &NetworkLockPrivateKey {
        &self.network_lock
    }

    pub fn backend_log_id(&self) -> &[u8; KEY_LEN] {
        &self.backend_log_id
    }

    fn from_key_material(material: [u8; KEY_LEN * KEY_COUNT]) -> Self {
        let key = |index: usize| {
            material[index * KEY_LEN..(index + 1) * KEY_LEN]
                .try_into()
                .expect("fixed-size key material")
        };
        Self {
            machine: PrivateKey::from_bytes(key(0)),
            node: PrivateKey::from_bytes(key(1)),
            disco: PrivateKey::from_bytes(key(2)),
            network_lock: NetworkLockPrivateKey::from_seed(key(3)),
            backend_log_id: key(4),
        }
    }
}

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("identity RNG failed: {0}")]
    Random(#[from] getrandom::Error),
    #[error("identity has invalid length {0}; expected {ENCODED_IDENTITY_LEN}")]
    InvalidLength(usize),
    #[error("identity format version {0} is unsupported")]
    UnsupportedVersion(u8),
}

#[cfg(test)]
mod tests {
    use super::{DeviceIdentity, IdentityError, ENCODED_IDENTITY_LEN};

    #[test]
    fn identity_round_trips_without_changing_public_keys() {
        let identity = DeviceIdentity::generate().unwrap();
        let decoded = DeviceIdentity::decode(&identity.encode()).unwrap();
        assert_eq!(
            decoded.machine_key().public(),
            identity.machine_key().public()
        );
        assert_eq!(decoded.node_key().public(), identity.node_key().public());
        assert_eq!(decoded.disco_key().public(), identity.disco_key().public());
        assert_eq!(decoded.backend_log_id(), identity.backend_log_id());
    }

    #[test]
    fn identity_decoder_rejects_bad_length_and_version() {
        assert!(matches!(
            DeviceIdentity::decode(&[0; 3]),
            Err(IdentityError::InvalidLength(3))
        ));
        let mut encoded = [0_u8; ENCODED_IDENTITY_LEN];
        encoded[0] = 9;
        assert!(matches!(
            DeviceIdentity::decode(&encoded),
            Err(IdentityError::UnsupportedVersion(9))
        ));
    }
}
