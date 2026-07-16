use blake2::{Blake2s256, Digest};
use minicbor::data::Type;
use minicbor::{Decoder, Encoder};
use thiserror::Error;
use zeroize::Zeroize;

use super::key::{NetworkLockPrivateKey, Node, PublicKey};

const SIG_DIRECT: u8 = 1;
const SIG_ROTATION: u8 = 2;
const SIG_CREDENTIAL: u8 = 3;
const MAX_NESTING: usize = 16;
const MAX_FIELD_SIZE: usize = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
struct NodeKeySignature {
    kind: u8,
    public_key: Vec<u8>,
    key_id: Vec<u8>,
    signature: Vec<u8>,
    nested: Option<Box<NodeKeySignature>>,
    wrapping_public_key: Vec<u8>,
}

impl NodeKeySignature {
    fn rotation(public_key: PublicKey<Node>, nested: Self) -> Self {
        Self {
            kind: SIG_ROTATION,
            public_key: node_key_binary(public_key),
            key_id: Vec::new(),
            signature: Vec::new(),
            nested: Some(Box::new(nested)),
            wrapping_public_key: Vec::new(),
        }
    }

    fn serialize(&self) -> Result<Vec<u8>, TailnetLockError> {
        let mut encoder = Encoder::new(Vec::new());
        encode_signature(&mut encoder, self)?;
        Ok(encoder.into_writer())
    }

    fn signature_hash(&self) -> Result<[u8; 32], TailnetLockError> {
        let mut unsigned = self.clone();
        unsigned.signature.zeroize();
        unsigned.signature.clear();
        Ok(Blake2s256::digest(unsigned.serialize()?).into())
    }

    fn sign(&mut self, key: &NetworkLockPrivateKey) -> Result<(), TailnetLockError> {
        self.signature = key.sign(&self.signature_hash()?).to_vec();
        Ok(())
    }
}

/// Re-signs the control server's existing node-key signature for a replacement
/// WireGuard node key. The encoded form is compatible with Tailscale's CTAP2
/// canonical CBOR `NodeKeySignature` representation.
pub fn resign_node_key_signature(
    key: &NetworkLockPrivateKey,
    replacement: PublicKey<Node>,
    old_signature: &[u8],
) -> Result<Vec<u8>, TailnetLockError> {
    let old = decode(old_signature)?;
    validate_signature_shape(&old, 0)?;
    if old.public_key == node_key_binary(replacement) {
        return Ok(old_signature.to_vec());
    }

    let nested = trim_rotation_chain(old, key)?;
    let mut signature = NodeKeySignature::rotation(replacement, nested);
    signature.sign(key)?;
    signature.serialize()
}

fn trim_rotation_chain(
    signature: NodeKeySignature,
    key: &NetworkLockPrivateKey,
) -> Result<NodeKeySignature, TailnetLockError> {
    if signature.kind != SIG_ROTATION || rotation_depth(&signature) < MAX_NESTING - 1 {
        return Ok(signature);
    }

    let mut previous_keys = Vec::new();
    let mut current = &signature;
    while current.kind == SIG_ROTATION {
        previous_keys.push(parse_node_key(&current.public_key)?);
        current = current
            .nested
            .as_deref()
            .ok_or(TailnetLockError::MissingNestedSignature)?;
    }
    let mut rebuilt = current.clone();
    for public_key in previous_keys.into_iter().take(14).rev() {
        let mut rotation = NodeKeySignature::rotation(public_key, rebuilt);
        rotation.sign(key)?;
        rebuilt = rotation;
    }
    Ok(rebuilt)
}

fn rotation_depth(signature: &NodeKeySignature) -> usize {
    let mut depth = 0;
    let mut current = Some(signature);
    while let Some(signature) = current {
        if signature.kind != SIG_ROTATION {
            break;
        }
        depth += 1;
        current = signature.nested.as_deref();
    }
    depth
}

fn parse_node_key(bytes: &[u8]) -> Result<PublicKey<Node>, TailnetLockError> {
    let bytes = bytes.strip_prefix(b"np").unwrap_or(bytes);
    let bytes = bytes
        .try_into()
        .map_err(|_| TailnetLockError::InvalidNodeKeyLength(bytes.len()))?;
    Ok(PublicKey::from_bytes(bytes))
}

fn node_key_binary(key: PublicKey<Node>) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(34);
    encoded.extend_from_slice(b"np");
    encoded.extend_from_slice(key.as_bytes());
    encoded
}

fn validate_signature_shape(
    signature: &NodeKeySignature,
    depth: usize,
) -> Result<(), TailnetLockError> {
    if depth >= MAX_NESTING {
        return Err(TailnetLockError::NestingTooDeep);
    }
    if !matches!(signature.kind, SIG_DIRECT | SIG_ROTATION | SIG_CREDENTIAL) {
        return Err(TailnetLockError::InvalidSignatureKind(signature.kind));
    }
    if signature.public_key.len() > MAX_FIELD_SIZE
        || signature.key_id.len() > MAX_FIELD_SIZE
        || signature.signature.len() > MAX_FIELD_SIZE
        || signature.wrapping_public_key.len() > MAX_FIELD_SIZE
    {
        return Err(TailnetLockError::FieldTooLarge);
    }
    if signature.kind == SIG_ROTATION {
        let nested = signature
            .nested
            .as_deref()
            .ok_or(TailnetLockError::MissingNestedSignature)?;
        parse_node_key(&signature.public_key)?;
        validate_signature_shape(nested, depth + 1)?;
    } else if signature.nested.is_some() {
        return Err(TailnetLockError::UnexpectedNestedSignature);
    }
    Ok(())
}

fn encode_signature(
    encoder: &mut Encoder<Vec<u8>>,
    signature: &NodeKeySignature,
) -> Result<(), TailnetLockError> {
    let field_count = 1
        + usize::from(!signature.public_key.is_empty())
        + usize::from(!signature.key_id.is_empty())
        + usize::from(!signature.signature.is_empty())
        + usize::from(signature.nested.is_some())
        + usize::from(!signature.wrapping_public_key.is_empty());
    encoder.map(field_count as u64)?.u8(1)?.u8(signature.kind)?;
    if !signature.public_key.is_empty() {
        encoder.u8(2)?.bytes(&signature.public_key)?;
    }
    if !signature.key_id.is_empty() {
        encoder.u8(3)?.bytes(&signature.key_id)?;
    }
    if !signature.signature.is_empty() {
        encoder.u8(4)?.bytes(&signature.signature)?;
    }
    if let Some(nested) = &signature.nested {
        encoder.u8(5)?;
        encode_signature(encoder, nested)?;
    }
    if !signature.wrapping_public_key.is_empty() {
        encoder.u8(6)?.bytes(&signature.wrapping_public_key)?;
    }
    Ok(())
}

fn decode(bytes: &[u8]) -> Result<NodeKeySignature, TailnetLockError> {
    let mut decoder = Decoder::new(bytes);
    let signature = decode_signature(&mut decoder, 0)?;
    if decoder.position() != bytes.len() {
        return Err(TailnetLockError::TrailingData);
    }
    Ok(signature)
}

fn decode_signature(
    decoder: &mut Decoder<'_>,
    depth: usize,
) -> Result<NodeKeySignature, TailnetLockError> {
    if depth >= MAX_NESTING {
        return Err(TailnetLockError::NestingTooDeep);
    }
    let length = decoder.map()?;
    let mut signature = NodeKeySignature {
        kind: 0,
        public_key: Vec::new(),
        key_id: Vec::new(),
        signature: Vec::new(),
        nested: None,
        wrapping_public_key: Vec::new(),
    };
    let mut read = 0;
    while length.is_none_or(|length| read < length) {
        if length.is_none() && decoder.datatype()? == Type::Break {
            decoder.skip()?;
            break;
        }
        read += 1;
        match decoder.u8()? {
            1 => signature.kind = decoder.u8()?,
            2 => signature.public_key = decode_bytes(decoder)?,
            3 => signature.key_id = decode_bytes(decoder)?,
            4 => signature.signature = decode_bytes(decoder)?,
            5 => signature.nested = Some(Box::new(decode_signature(decoder, depth + 1)?)),
            6 => signature.wrapping_public_key = decode_bytes(decoder)?,
            _ => decoder.skip()?,
        }
    }
    Ok(signature)
}

fn decode_bytes(decoder: &mut Decoder<'_>) -> Result<Vec<u8>, TailnetLockError> {
    let bytes = decoder.bytes()?;
    if bytes.len() > MAX_FIELD_SIZE {
        return Err(TailnetLockError::FieldTooLarge);
    }
    Ok(bytes.to_vec())
}

#[derive(Debug, Error)]
pub enum TailnetLockError {
    #[error("invalid tailnet-lock CBOR: {0}")]
    Decode(#[from] minicbor::decode::Error),
    #[error("could not encode tailnet-lock CBOR: {0}")]
    Encode(#[from] minicbor::encode::Error<std::convert::Infallible>),
    #[error("tailnet-lock signature nesting exceeds {MAX_NESTING} levels")]
    NestingTooDeep,
    #[error("tailnet-lock signature has invalid kind {0}")]
    InvalidSignatureKind(u8),
    #[error("tailnet-lock rotation signature is missing its nested signature")]
    MissingNestedSignature,
    #[error("non-rotation tailnet-lock signature has a nested signature")]
    UnexpectedNestedSignature,
    #[error("tailnet-lock signature contains an oversized field")]
    FieldTooLarge,
    #[error("tailnet-lock node key has invalid length {0}")]
    InvalidNodeKeyLength(usize),
    #[error("tailnet-lock signature contains trailing data")]
    TrailingData,
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    use super::{decode, resign_node_key_signature, NodeKeySignature, SIG_DIRECT, SIG_ROTATION};
    use crate::key::{NetworkLockPrivateKey, Node, PublicKey};

    fn direct_signature(node: PublicKey<Node>, wrapping_key: &[u8]) -> Vec<u8> {
        NodeKeySignature {
            kind: SIG_DIRECT,
            public_key: node.as_bytes().to_vec(),
            key_id: vec![4; 32],
            signature: vec![5; 64],
            nested: None,
            wrapping_public_key: wrapping_key.to_vec(),
        }
        .serialize()
        .unwrap()
    }

    #[test]
    fn creates_verifiable_canonical_rotation_signature() {
        let lock_key = NetworkLockPrivateKey::from_seed([7; 32]);
        let old_node = PublicKey::<Node>::from_bytes([8; 32]);
        let new_node = PublicKey::<Node>::from_bytes([9; 32]);
        let old = direct_signature(old_node, lock_key.public().as_bytes());
        let encoded = resign_node_key_signature(&lock_key, new_node, &old).unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.kind, SIG_ROTATION);
        assert_eq!(&decoded.public_key[2..], new_node.as_bytes());
        assert_eq!(
            decoded.nested.as_ref().unwrap().public_key,
            old_node.as_bytes()
        );

        let hash = decoded.signature_hash().unwrap();
        let verifying_key = VerifyingKey::from_bytes(lock_key.public().as_bytes()).unwrap();
        let signature = Signature::try_from(decoded.signature.as_slice()).unwrap();
        verifying_key.verify(&hash, &signature).unwrap();
    }

    #[test]
    fn returns_existing_signature_when_the_node_key_is_unchanged() {
        let lock_key = NetworkLockPrivateKey::from_seed([7; 32]);
        let node = PublicKey::<Node>::from_bytes([8; 32]);
        let mut direct = decode(&direct_signature(node, lock_key.public().as_bytes())).unwrap();
        direct.public_key = super::node_key_binary(node);
        let signature = direct.serialize().unwrap();
        assert_eq!(
            resign_node_key_signature(&lock_key, node, &signature).unwrap(),
            signature
        );
    }

    #[test]
    fn matches_the_official_go_implementation_vector() {
        let initial = decode_hex(
            "a501010258200808080808080808080808080808080808080808080808080808080808080808035820040404040404040404040404040404040404040404040404040404040404040404584005050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505065820ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
        );
        let expected = decode_hex(
            "a401020258226e7009090909090909090909090909090909090909090909090909090909090909090458404efa2d6ce0ecf1f05074c958b15fb7688dc7cc3337d645c5ca403f789a326e2a6dc349369bed581760b436c5084b22560145052a9adbe749f4d0a3b950054a0205a501010258200808080808080808080808080808080808080808080808080808080808080808035820040404040404040404040404040404040404040404040404040404040404040404584005050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505065820ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
        );
        let lock_key = NetworkLockPrivateKey::from_seed([7; 32]);
        let replacement = PublicKey::<Node>::from_bytes([9; 32]);
        assert_eq!(
            resign_node_key_signature(&lock_key, replacement, &initial).unwrap(),
            expected
        );
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let pair = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(pair, 16).unwrap()
            })
            .collect()
    }
}
