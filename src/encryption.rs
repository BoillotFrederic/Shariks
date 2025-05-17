//! # Encryption Module - Shariks Chain
//!
//! The `encryption` module handles all cryptographic operations necessary for
//! secure transactions, wallet authentication, and chain integrity within the Shariks blockchain.

// Dependencies
use base64::{Engine, engine::general_purpose};
use bip39::Mnemonic;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hex;
use rand_core::RngCore;
use sqlx::PgPool;
use std::convert::TryInto;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

// Encryption
// ----------

pub struct Encryption;

impl Encryption {
    /// Encrypt a message with the DH secret and DH public keys
    pub fn encrypt_message(
        sender_secret: &StaticSecret,
        recipient_public: &XPublicKey,
        message: &str,
    ) -> (String, [u8; 24]) {
        if message.is_empty() {
            ("".to_string(), [0u8; 24])
        } else {
            let shared_secret = sender_secret.diffie_hellman(recipient_public);
            let cipher = XChaCha20Poly1305::new_from_slice(shared_secret.as_bytes()).unwrap();

            let mut nonce = [0u8; 24];
            rand::rngs::OsRng.fill_bytes(&mut nonce);

            let ciphertext = cipher
                .encrypt(&XNonce::from(nonce), message.as_bytes())
                .unwrap();

            (general_purpose::STANDARD.encode(ciphertext), nonce)
        }
    }

    /// Decrypt a message with the correct DH secret and DH public keys
    pub fn decrypt_message(
        dh_secret: StaticSecret,
        dh_public: &XPublicKey,
        ciphertext_b64: &str,
        nonce: [u8; 24],
    ) -> Option<String> {
        let shared_secret = dh_secret.diffie_hellman(dh_public);
        let cipher = XChaCha20Poly1305::new_from_slice(shared_secret.as_bytes()).unwrap();

        let ciphertext = general_purpose::STANDARD.decode(ciphertext_b64).ok()?;
        let decrypted = cipher
            .decrypt(&XNonce::from(nonce), ciphertext.as_ref())
            .ok()?;

        String::from_utf8(decrypted).ok()
    }

    /// Generates a mnemonic and a public key associated with a private key, encapsulates
    /// in the encryption a secret DH key and a public DH key
    pub fn generate_full_keypair_from_mnemonic(
        passphrase: &str,
    ) -> (String, SigningKey, VerifyingKey, StaticSecret, XPublicKey) {
        let mnemonic = Mnemonic::generate(12).unwrap();
        let phrase = mnemonic.to_string();
        let seed = mnemonic.to_seed(passphrase);

        // Ed25519 keypair
        let seed_ed: &[u8; 32] = &seed[..32].try_into().expect("Error : seed < 32 bytes");
        let signing_key = SigningKey::from_bytes(seed_ed);
        let verifying_key = signing_key.verifying_key();

        // X25519 keypair for memo encryption
        let seed_dh: &[u8; 32] = &seed[32..64].try_into().expect("Error : seed < 64 bytes");
        let dh_secret = StaticSecret::from(*seed_dh);
        let dh_public = XPublicKey::from(&dh_secret);

        (phrase, signing_key, verifying_key, dh_secret, dh_public)
    }

    /// Remove the public key, private key, DU secret key and public DH key using the mnemonic
    /// and the seed
    pub fn restore_full_keypair_from_mnemonic(
        phrase: &str,
        passphrase: &str,
    ) -> Result<(SigningKey, VerifyingKey, StaticSecret, XPublicKey), String> {
        let mnemonic = Mnemonic::parse(phrase).expect("Error : invalid mnemonic phrase");
        let seed = mnemonic.to_seed(passphrase);

        // Ed25519 keypair
        let seed_ed: [u8; 32] = seed[..32].try_into().expect("Error : seed < 32 bytes");
        let signing_key = SigningKey::from_bytes(&seed_ed);
        let verifying_key = signing_key.verifying_key();

        // X25519 keypair for memo encryption
        let seed_dh: [u8; 32] = seed[32..64].try_into().expect("Error : seed < 64 bytes");
        let dh_secret = StaticSecret::from(seed_dh);
        let dh_public = XPublicKey::from(&dh_secret);

        Ok((signing_key, verifying_key, dh_secret, dh_public))
    }

    /// Sign a transaction with a private key and other parameters
    pub fn sign_transaction(
        private_key: String,
        sender: String,
        recipient: String,
        amount: u64,
        memo: String,
    ) -> String {
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
        let message = format!("{}:{}:{}:{}", sender, recipient, amount, memo);
        let signature: Signature = signing_key.sign(message.as_bytes());
        hex::encode(signature.to_bytes())
    }

    /// Verify the transaction signature using the public key
    pub fn verify_transaction(public_key_hex: &str, message: &str, signature_hex: &str) -> bool {
        // Erros
        let public_key_bytes = match hex::decode(public_key_hex) {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        let public_key_array: [u8; 32] = match public_key_bytes.try_into() {
            Ok(array) => array,
            Err(_) => return false,
        };
        let verifying_key = match VerifyingKey::from_bytes(&public_key_array) {
            Ok(key) => key,
            Err(_) => return false,
        };
        let signature_bytes = match hex::decode(signature_hex) {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        let signature_array: [u8; 64] = match signature_bytes.try_into() {
            Ok(array) => array,
            Err(_) => return false,
        };

        // Check the signature
        let signature = Signature::from_bytes(&signature_array);
        verifying_key.verify(message.as_bytes(), &signature).is_ok()
    }

    /// Find the public DH in hex and XPublicKey
    pub async fn get_dh_public_key_data_by_address(
        pool: &PgPool,
        address: &str,
    ) -> Result<(String, Option<XPublicKey>), sqlx::Error> {
        let result = sqlx::query!(
            r#"
        SELECT dh_public
        FROM wallets
        WHERE address = $1
        "#,
            address
        )
        .fetch_optional(pool)
        .await?;

        if let Some(row) = result {
            if let Some(dh_hex) = row.dh_public {
                // XPublicKey decode
                let dh_key = Self::hex_to_xpubkey(&dh_hex);

                Ok((dh_hex, dh_key))
            } else {
                // Null field
                Ok(("".to_string(), None))
            }
        } else {
            // Nothing found
            Ok(("".to_string(), None))
        }
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
