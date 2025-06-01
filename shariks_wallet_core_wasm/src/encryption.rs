// Dependencies
use bip39::Mnemonic;
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::convert::TryInto;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

// Types
type DynError = Box<dyn std::error::Error>;

// Handler
// -------

pub struct Encryption;

impl Encryption {
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
}
