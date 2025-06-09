// Dependencies
use base64::{Engine, engine::general_purpose};
use bip39::Mnemonic;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::RngCore;
use std::convert::TryInto;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

// Types
type DynError = Box<dyn std::error::Error>;

// Handler
// -------

pub struct Encryption;

impl Encryption {
    /// Encrypt a message with the DH secret and DH public keys
    pub fn encrypt_message(
        dh_secret: &StaticSecret,
        dh_public: &XPublicKey,
        message: &str,
    ) -> (String, [u8; 24]) {
        if message.is_empty() {
            ("".to_string(), [0u8; 24])
        } else {
            let shared_secret = dh_secret.diffie_hellman(dh_public);
            let cipher = match XChaCha20Poly1305::new_from_slice(shared_secret.as_bytes()) {
                Ok(c) => c,
                Err(_) => {
                    return ("".to_string(), [0u8; 24]);
                }
            };

            let mut nonce = [0u8; 24];
            rand::rngs::OsRng.fill_bytes(&mut nonce);

            let ciphertext = match cipher.encrypt(&XNonce::from(nonce), message.as_bytes()) {
                Ok(data) => data,
                Err(_) => {
                    return ("".to_string(), [0u8; 24]);
                }
            };

            (general_purpose::STANDARD.encode(ciphertext), nonce)
        }
    }

    /// Decrypt a message with the correct DH secret and DH public keys
    pub fn decrypt_message(
        dh_secret: StaticSecret,
        dh_public: &XPublicKey,
        ciphertext_b64: &str,
        nonce: [u8; 24],
    ) -> Result<String, DynError> {
        let shared_secret = dh_secret.diffie_hellman(dh_public);
        let cipher = XChaCha20Poly1305::new_from_slice(shared_secret.as_bytes())
            .map_err(|_| "Cipher init failed")?;

        let ciphertext = general_purpose::STANDARD
            .decode(ciphertext_b64)
            .map_err(|_| "Base64 decode failed")?;

        let decrypted = cipher
            .decrypt(&XNonce::from(nonce), ciphertext.as_ref())
            .map_err(|_| "Decryption failed")?;

        let text = String::from_utf8(decrypted).map_err(|_| "UTF-8 conversion failed")?;
        Ok(text)
    }

    /// Generates a mnemonic and a public key associated with a private key, encapsulates
    /// in the encryption a secret DH key and a public DH key
    pub fn generate_full_keypair_from_mnemonic(
        passphrase: &str,
    ) -> Result<(String, SigningKey, VerifyingKey, StaticSecret, XPublicKey), DynError> {
        let mnemonic = Mnemonic::generate(12)?;
        let phrase = mnemonic.to_string();
        let seed = mnemonic.to_seed(passphrase);

        // Ed25519 keypair
        let seed_ed: &[u8; 32] = &seed[..32].try_into().map_err(|_| "seed < 32 bytes")?;
        let signing_key = SigningKey::from_bytes(seed_ed);
        let verifying_key = signing_key.verifying_key();

        // X25519 keypair for memo encryption
        let seed_dh: &[u8; 32] = &seed[32..64].try_into().map_err(|_| "seed < 64 bytes")?;
        let dh_secret = StaticSecret::from(*seed_dh);
        let dh_public = XPublicKey::from(&dh_secret);

        Ok((phrase, signing_key, verifying_key, dh_secret, dh_public))
    }

    /// Remove the public key, private key, DU secret key and public DH key using the mnemonic
    /// and the seed
    pub fn restore_full_keypair_from_mnemonic(
        phrase: &str,
        passphrase: &str,
    ) -> Result<(SigningKey, VerifyingKey, StaticSecret, XPublicKey), DynError> {
        let mnemonic = Mnemonic::parse(phrase).map_err(|_e| "Invalid mnemonic phrase")?;
        let seed = mnemonic.to_seed(passphrase);

        // Ed25519 keypair
        let seed_ed: [u8; 32] = seed[..32]
            .try_into()
            .map_err(|_| "Seed slice too short for Ed25519 key")?;
        let signing_key = SigningKey::from_bytes(&seed_ed);
        let verifying_key = signing_key.verifying_key();

        // X25519 keypair for memo encryption
        let seed_dh: [u8; 32] = seed[32..64]
            .try_into()
            .map_err(|_| "Seed slice too short for X25519 key")?;
        let dh_secret = StaticSecret::from(seed_dh);
        let dh_public = XPublicKey::from(&dh_secret);

        Ok((signing_key, verifying_key, dh_secret, dh_public))
    }

    /// Sign with a private key and message
    pub fn create_signature(private_key: String, message: String) -> String {
        // Errors
        let key_bytes = match hex::decode(private_key.trim()) {
            Ok(bytes) => bytes,
            Err(_) => return String::new(),
        };

        let key_array: [u8; 32] = match key_bytes.try_into() {
            Ok(array) => array,
            Err(_) => return String::new(),
        };

        // Sign
        let signing_key = SigningKey::from_bytes(&key_array);
        let signature: Signature = signing_key.sign(message.as_bytes());
        hex::encode(signature.to_bytes())
    }

    /// String to StaticSecrets
    pub fn hex_to_static_secret(hex: &str) -> Option<StaticSecret> {
        let bytes = hex::decode(hex).ok()?;
        let arr: [u8; 32] = bytes.try_into().ok()?;
        Some(StaticSecret::from(arr))
    }

    /// String to XPublicKey
    pub fn hex_to_xpubkey(hex: &str) -> Option<XPublicKey> {
        let bytes = hex::decode(hex).ok()?;
        let arr: [u8; 32] = bytes.try_into().ok()?;
        Some(XPublicKey::from(arr))
    }

    /// String to nonce
    pub fn b64_to_nonce(b64: &str) -> Option<[u8; 24]> {
        let bytes = general_purpose::STANDARD.decode(b64).ok()?;
        bytes.try_into().ok()
    }
}
