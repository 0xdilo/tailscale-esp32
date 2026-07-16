use blake2::{Blake2s256, Digest};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce, Tag};
use rand_core::{CryptoRng, OsRng, RngCore};
use snow::params::{CipherChoice, DHChoice, HashChoice, NoiseParams};
use snow::resolvers::CryptoResolver;
use snow::types::{Cipher, Dh, Hash, Random};
use snow::{Builder, Error};
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};
use zeroize::{Zeroize, ZeroizeOnDrop};

const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;

pub(crate) fn noise_builder<'a>(params: NoiseParams) -> Builder<'a> {
    Builder::with_resolver(params, Box::new(ConstrainedResolver))
}

struct ConstrainedResolver;

impl CryptoResolver for ConstrainedResolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        Some(Box::new(SystemRandom(OsRng)))
    }

    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        (*choice == DHChoice::Curve25519).then(|| Box::new(Dh25519::default()) as Box<dyn Dh>)
    }

    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        (*choice == HashChoice::Blake2s).then(|| Box::new(HashBlake2s::default()) as Box<dyn Hash>)
    }

    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        (*choice == CipherChoice::ChaChaPoly)
            .then(|| Box::new(CipherChaChaPoly::default()) as Box<dyn Cipher>)
    }
}

struct SystemRandom(OsRng);

impl RngCore for SystemRandom {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        self.0.fill_bytes(destination);
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.try_fill_bytes(destination)
    }
}

impl CryptoRng for SystemRandom {}
impl Random for SystemRandom {}

#[derive(Default, Zeroize, ZeroizeOnDrop)]
struct Dh25519 {
    private: [u8; KEY_LEN],
    public: [u8; KEY_LEN],
}

impl Dh25519 {
    fn derive_public(&mut self) {
        self.public = x25519(self.private, X25519_BASEPOINT_BYTES);
    }
}

impl Dh for Dh25519 {
    fn name(&self) -> &'static str {
        "25519"
    }

    fn pub_len(&self) -> usize {
        KEY_LEN
    }

    fn priv_len(&self) -> usize {
        KEY_LEN
    }

    fn set(&mut self, private: &[u8]) {
        if private.len() == KEY_LEN {
            self.private.copy_from_slice(private);
            self.derive_public();
        }
    }

    fn generate(&mut self, rng: &mut dyn Random) {
        rng.fill_bytes(&mut self.private);
        self.derive_public();
    }

    fn pubkey(&self) -> &[u8] {
        &self.public
    }

    fn privkey(&self) -> &[u8] {
        &self.private
    }

    fn dh(&self, public: &[u8], output: &mut [u8]) -> Result<(), Error> {
        let public: [u8; KEY_LEN] = public
            .get(..KEY_LEN)
            .ok_or(Error::Dh)?
            .try_into()
            .expect("slice is exactly one X25519 key");
        let shared = x25519(self.private, public);
        if shared == [0; KEY_LEN] || output.len() < KEY_LEN {
            return Err(Error::Dh);
        }
        output[..KEY_LEN].copy_from_slice(&shared);
        Ok(())
    }
}

#[derive(Default, Zeroize, ZeroizeOnDrop)]
struct CipherChaChaPoly {
    key: [u8; KEY_LEN],
}

impl Cipher for CipherChaChaPoly {
    fn name(&self) -> &'static str {
        "ChaChaPoly"
    }

    fn set(&mut self, key: &[u8]) {
        if key.len() == KEY_LEN {
            self.key.copy_from_slice(key);
        }
    }

    fn encrypt(&self, nonce: u64, auth: &[u8], plaintext: &[u8], output: &mut [u8]) -> usize {
        let mut nonce_bytes = [0_u8; 12];
        nonce_bytes[4..].copy_from_slice(&nonce.to_le_bytes());
        output[..plaintext.len()].copy_from_slice(plaintext);
        let tag = ChaCha20Poly1305::new((&self.key).into())
            .encrypt_in_place_detached(
                Nonce::from_slice(&nonce_bytes),
                auth,
                &mut output[..plaintext.len()],
            )
            .expect("Snow provides a correctly sized ChaCha20-Poly1305 output");
        output[plaintext.len()..plaintext.len() + TAG_LEN].copy_from_slice(&tag);
        plaintext.len() + TAG_LEN
    }

    fn decrypt(
        &self,
        nonce: u64,
        auth: &[u8],
        ciphertext: &[u8],
        output: &mut [u8],
    ) -> Result<usize, Error> {
        let message_len = ciphertext
            .len()
            .checked_sub(TAG_LEN)
            .ok_or(Error::Decrypt)?;
        if output.len() < message_len {
            return Err(Error::Decrypt);
        }
        let mut nonce_bytes = [0_u8; 12];
        nonce_bytes[4..].copy_from_slice(&nonce.to_le_bytes());
        output[..message_len].copy_from_slice(&ciphertext[..message_len]);
        ChaCha20Poly1305::new((&self.key).into())
            .decrypt_in_place_detached(
                Nonce::from_slice(&nonce_bytes),
                auth,
                &mut output[..message_len],
                Tag::from_slice(&ciphertext[message_len..]),
            )
            .map_err(|_| Error::Decrypt)?;
        Ok(message_len)
    }
}

#[derive(Default)]
struct HashBlake2s(Blake2s256);

impl Hash for HashBlake2s {
    fn name(&self) -> &'static str {
        "BLAKE2s"
    }

    fn block_len(&self) -> usize {
        64
    }

    fn hash_len(&self) -> usize {
        32
    }

    fn reset(&mut self) {
        self.0 = Blake2s256::new();
    }

    fn input(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn result(&mut self, output: &mut [u8]) {
        output[..32].copy_from_slice(&self.0.finalize_reset());
    }
}
