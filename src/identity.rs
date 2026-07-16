use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::key::{Disco, Machine, NetworkLockPrivateKey, Node, PrivateKey, PublicKey};

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

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct NodeKeyRotation {
    #[zeroize(skip)]
    old_public: PublicKey<Node>,
    replacement: PrivateKey<Node>,
}

impl NodeKeyRotation {
    pub fn old_public(&self) -> PublicKey<Node> {
        self.old_public
    }

    pub fn replacement(&self) -> &PrivateKey<Node> {
        &self.replacement
    }
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

    /// Generates a replacement node key without changing the active identity.
    /// Persist the value returned by [`Self::rotated`] before using it for data
    /// traffic, so a power loss cannot leave control and flash out of sync.
    pub fn prepare_node_key_rotation(&self) -> Result<NodeKeyRotation, IdentityError> {
        let mut bytes = [0_u8; KEY_LEN];
        getrandom::getrandom(&mut bytes)?;
        Ok(NodeKeyRotation {
            old_public: self.node.public(),
            replacement: PrivateKey::from_bytes(bytes),
        })
    }

    /// Returns a copy with an accepted replacement node key installed.
    pub fn rotated(&self, rotation: &NodeKeyRotation) -> Result<Self, IdentityError> {
        if rotation.old_public != self.node.public() {
            return Err(IdentityError::StaleRotation);
        }
        let mut identity = self.clone();
        identity.node = rotation.replacement.clone();
        Ok(identity)
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
    #[error("node-key rotation was prepared for a different active key")]
    StaleRotation,
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

    #[test]
    fn node_key_rotation_is_transactional_and_persistent() {
        let identity = DeviceIdentity::generate().unwrap();
        let old_key = identity.node_key().public();
        let rotation = identity.prepare_node_key_rotation().unwrap();
        assert_eq!(identity.node_key().public(), old_key);
        assert_eq!(rotation.old_public(), old_key);
        assert_ne!(rotation.replacement().public(), old_key);

        let rotated = identity.rotated(&rotation).unwrap();
        let restored = DeviceIdentity::decode(&rotated.encode()).unwrap();
        assert_eq!(
            restored.node_key().public(),
            rotation.replacement().public()
        );
        assert_eq!(
            restored.machine_key().public(),
            identity.machine_key().public()
        );
    }
}
