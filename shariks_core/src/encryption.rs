//! # Encryption Module - Shariks Chain
//!
//! The `encryption` module handles all cryptographic operations necessary for
//! secure transactions, wallet authentication, and chain integrity within the Shariks blockchain.

// Dependencies
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
use base64::{Engine, engine::general_purpose};
use bip39::Mnemonic;
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hex;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use std::convert::TryInto;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

// Crates
use crate::log::*;
use crate::utils::*;
use crate::wallet::Wallet;

// Types
type DynError = Box<dyn std::error::Error>;

#[derive(Serialize, Deserialize)]
pub struct EncryptedPayload {
    pub encrypted_data: String,
    pub salt: String,
    pub nonce: String,
    pub kdf: &'static str,
}

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
            let cipher = match XChaCha20Poly1305::new_from_slice(shared_secret.as_bytes()) {
                Ok(c) => c,
                Err(e) => {
                    Log::error(
                        "Encryption",
                        "encrypt_message",
                        "Invalid key size for cipher",
                        e,
                    );
                    return ("".to_string(), [0u8; 24]);
                }
            };

            let mut nonce = [0u8; 24];
            rand::rngs::OsRng.fill_bytes(&mut nonce);

            let ciphertext = match cipher.encrypt(&XNonce::from(nonce), message.as_bytes()) {
                Ok(data) => data,
                Err(e) => {
                    Log::error("Encryption", "encrypt_message", "Encryption failed", e);
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
    ) -> Option<String> {
        let shared_secret = dh_secret.diffie_hellman(dh_public);
        let cipher = match XChaCha20Poly1305::new_from_slice(shared_secret.as_bytes()) {
            Ok(c) => c,
            Err(e) => {
                Log::error(
                    "Encryption",
                    "decrypt_message",
                    "Invalid key size for cipher",
                    e,
                );
                return None;
            }
        };

        let ciphertext = match general_purpose::STANDARD.decode(ciphertext_b64) {
            Ok(data) => data,
            Err(e) => {
                Log::error("Encryption", "decrypt_message", "Invalid b64", e);
                return None;
            }
        };

        let decrypted = match cipher.decrypt(&XNonce::from(nonce), ciphertext.as_ref()) {
            Ok(data) => data,
            Err(e) => {
                Log::error("Encryption", "decrypt_message", "invalid key or nonce", e);
                return None;
            }
        };

        match String::from_utf8(decrypted) {
            Ok(text) => Some(text),
            Err(e) => {
                Log::error("Encryption", "decrypt_message", "invalid UTF-8", e);
                return None;
            }
        }
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
    pub async fn restore_full_keypair_from_mnemonic(
        phrase: &str,
        passphrase: &str,
        pool: &PgPool,
    ) -> Result<(SigningKey, VerifyingKey, StaticSecret, XPublicKey), String> {
        let mnemonic = Mnemonic::parse(phrase).map_err(|e| {
            Log::error(
                "Encryption",
                "restore_wallet",
                "Invalid mnemonic phrase",
                e.to_string(),
            );
            "Invalid mnemonic phrase"
        })?;
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

        let address = hex::encode(verifying_key.to_bytes());
        let exists = Wallet::exists(pool, &Wallet::add_prefix(&address))
            .await
            .map_err(|e| format!("Error while checking wallet existence: {}", e))?;

        if !exists {
            return Err("Error: wallet does not exist".to_string());
        }

        Ok((signing_key, verifying_key, dh_secret, dh_public))
    }

    /// Sign a message with a private key
    pub fn sign_message(private_key: String, message: String) -> String {
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

    // /// Sign a transaction with a private key and other parameters
    // pub fn sign_transaction(
    //     private_key: String,
    //     sender: String,
    //     recipient: String,
    //     amount: u64,
    //     memo: String,
    // ) -> String {
    //     // Errors
    //     let key_bytes = match hex::decode(private_key.trim()) {
    //         Ok(bytes) => bytes,
    //         Err(_) => return String::new(),
    //     };
    //
    //     let key_array: [u8; 32] = match key_bytes.try_into() {
    //         Ok(array) => array,
    //         Err(_) => return String::new(),
    //     };
    //
    //     // Sign
    //     let signing_key = SigningKey::from_bytes(&key_array);
    //     let message = format!("{}:{}:{}:{}", sender, recipient, amount, memo);
    //     let signature: Signature = signing_key.sign(message.as_bytes());
    //     hex::encode(signature.to_bytes())
    // }

    /// Verify the transaction signature using the public key
    pub fn verify_signature(public_key_hex: &str, message: &str, signature_hex: &str) -> bool {
        // Errors
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

    // /// Verify the transaction signature using the public key
    // pub fn verify_signature(public_key_hex: &str, message: &str, signature_hex: &str) -> bool {
    //     // Erros
    //     let public_key_bytes = match hex::decode(public_key_hex) {
    //         Ok(bytes) => bytes,
    //         Err(_) => return false,
    //     };
    //     let public_key_array: [u8; 32] = match public_key_bytes.try_into() {
    //         Ok(array) => array,
    //         Err(_) => return false,
    //     };
    //     let verifying_key = match VerifyingKey::from_bytes(&public_key_array) {
    //         Ok(key) => key,
    //         Err(_) => return false,
    //     };
    //     let signature_bytes = match hex::decode(signature_hex) {
    //         Ok(bytes) => bytes,
    //         Err(_) => return false,
    //     };
    //     let signature_array: [u8; 64] = match signature_bytes.try_into() {
    //         Ok(array) => array,
    //         Err(_) => return false,
    //     };
    //
    //     // Check the signature
    //     let signature = Signature::from_bytes(&signature_array);
    //     verifying_key.verify(message.as_bytes(), &signature).is_ok()
    // }

    /// Find the public DH in hex and XPublicKey
    pub async fn get_dh_public_key_data_by_address(
        pool: &PgPool,
        address: &str,
    ) -> Result<(String, Option<XPublicKey>), sqlx::Error> {
        let result = Utils::with_timeout(
            sqlx::query!(
                r#"
                SELECT dh_public
                FROM core.wallets
                WHERE address = $1
                "#,
                address
            )
            .fetch_optional(pool),
            30,
        )
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

    pub fn encrypt_json(json: &Value, passphrase: &str) -> EncryptedPayload {
        let salt = SaltString::generate(&mut rand::rngs::OsRng);
        let argon2 = Argon2::default();

        let password_hash = argon2
            .hash_password(passphrase.as_bytes(), &salt)
            .expect("Password hashing failed");

        let hash = password_hash.hash.expect("Missing hash output");
        let key_bytes = hash.as_bytes();
        let key = Key::from_slice(&key_bytes[..32]);

        let mut nonce = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let cipher = XChaCha20Poly1305::new(key);

        let payload = serde_json::to_vec(json).expect("Serialization failed");
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &payload,
                    aad: &[],
                },
            )
            .expect("Encryption failed");

        EncryptedPayload {
            encrypted_data: general_purpose::STANDARD.encode(ciphertext),
            salt: salt.to_string(),
            nonce: general_purpose::STANDARD.encode(nonce),
            kdf: "argon2",
        }
    }

    pub fn decrypt_json(payload: &EncryptedPayload, passphrase: &str) -> Result<Value, String> {
        let salt = SaltString::from_b64(&payload.salt).map_err(|_| "Invalid salt".to_string())?;

        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(passphrase.as_bytes(), &salt)
            .map_err(|_| "Failed to hash password".to_string())?;

        let hash = password_hash
            .hash
            .ok_or_else(|| "Missing hash output".to_string())?;

        let key_bytes = hash.as_bytes();

        let key = Key::from_slice(&key_bytes[..32]);
        let cipher = XChaCha20Poly1305::new(key);

        let nonce_bytes = general_purpose::STANDARD
            .decode(&payload.nonce)
            .map_err(|_| "Invalid nonce base64".to_string())?;

        let ciphertext = general_purpose::STANDARD
            .decode(&payload.encrypted_data)
            .map_err(|_| "Invalid encrypted data base64".to_string())?;

        let decrypted = cipher
            .decrypt(
                XNonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &ciphertext,
                    aad: &[],
                },
            )
            .map_err(|_| "Decryption failed".to_string())?;

        serde_json::from_slice::<Value>(&decrypted)
            .map_err(|_| "Invalid JSON after decryption".to_string())
    }
}
