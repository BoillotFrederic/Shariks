// Crates
use crate::encryption::*;

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
}
