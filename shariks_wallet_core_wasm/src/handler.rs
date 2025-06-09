// Crates
use crate::encryption::*;
use base64::Engine;

// Types
type DynError = Box<dyn std::error::Error>;

// Handler
// -------

pub struct Handler;

impl Handler {
    /// Create a new wallet keys
    pub fn new_wallet_keys(
        passphrase: &str,
    ) -> Result<(String, String, String, String, String), DynError> {
        // Keypair generate
        let (phrase, signing_key, verifying_key, dh_secret, dh_public) =
            match Encryption::generate_full_keypair_from_mnemonic(passphrase) {
                Ok(keys) => keys,
                Err(e) => {
                    return Err(e);
                }
            };

        let private_key_bytes = signing_key.to_bytes();
        let public_key_bytes = verifying_key.to_bytes();

        Ok((
            phrase,                            // Mnemonic
            hex::encode(public_key_bytes),     // Public key
            hex::encode(private_key_bytes),    // Private key
            hex::encode(dh_public.as_bytes()), // DH public
            hex::encode(dh_secret.to_bytes()), // DH secret
        ))
    }

    /// Restore wallet keys
    pub fn restore_wallet_keys(
        phrase: &str,
        passphrase: &str,
    ) -> Result<(String, String, String, String), DynError> {
        // Keypair restore
        let (signing_key, verifying_key, dh_secret, dh_public) =
            match Encryption::restore_full_keypair_from_mnemonic(phrase, passphrase) {
                Ok(keys) => keys,
                Err(e) => {
                    return Err(e);
                }
            };

        let private_key_bytes = signing_key.to_bytes();
        let public_key_bytes = verifying_key.to_bytes();

        Ok((
            hex::encode(public_key_bytes),     // Public key
            hex::encode(private_key_bytes),    // Private key
            hex::encode(dh_public.as_bytes()), // DH public
            hex::encode(dh_secret.to_bytes()), // DH secret
        ))
    }

    /// Encrypt a memo
    pub fn encryption_memo(
        dh_secret: &str,
        dh_public: &str,
        memo_input: &str,
    ) -> Result<String, DynError> {
        let sender_dh_secret = Encryption::hex_to_static_secret(dh_secret).unwrap();
        let recipient_dh_public = Encryption::hex_to_xpubkey(dh_public).unwrap();

        let (encrypted_memo, nonce) =
            Encryption::encrypt_message(&sender_dh_secret, &recipient_dh_public, &memo_input);

        let nonce_encoded = base64::engine::general_purpose::STANDARD.encode(nonce);
        let memo = if encrypted_memo.is_empty() {
            "".to_string()
        } else {
            format!("{}:{}", encrypted_memo, nonce_encoded)
        };

        Ok(memo)
    }

    /// Decrypt a memo
    pub fn decryption_memo(
        dh_secret: &str,
        dh_public: &str,
        memo: &str,
    ) -> Result<String, DynError> {
        let (memo_b64, nonce_b64) = memo
            .split_once(':')
            .ok_or("Invalid memo format (missing ':')")?;

        let secret =
            Encryption::hex_to_static_secret(dh_secret).ok_or("Invalid dh_secret format")?;
        let pubkey = Encryption::hex_to_xpubkey(dh_public).ok_or("Invalid dh_public format")?;
        let nonce = Encryption::b64_to_nonce(nonce_b64).ok_or("Invalid nonce base64")?;

        Encryption::decrypt_message(secret, &pubkey, memo_b64, nonce)
    }
}
