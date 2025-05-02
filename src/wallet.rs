// Dependencies
use bip39::Mnemonic;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hex;
use once_cell::sync::Lazy;
//use rand::rngs::OsRng;
//use base64::decode;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::convert::TryInto;
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::io::{BufReader, BufWriter};
use std::sync::Mutex;

// Crate
use crate::blockchain::PREFIX_ADDRESS;
use crate::increment_file;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Wallet {
    pub address: String,
    pub referrer: String,
    pub first_referrer: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WalletOwner {
    pub public_key: String,
    pub private_key: String,
}

// Global
pub const WALLET_GENESIS: &str = "SRKS_genesis";

// Exempt fee wallet
pub static EXEMPT_FEES_ADDRESSES: Lazy<Mutex<HashSet<String>>> = Lazy::new(|| {
    let mut set = HashSet::new();
    set.insert("SRKS_eb1dd7df0b1d0b3a6d692cd04f17f805039b5a93a373a3d82daa04f43e1fe701".to_string());
    set.insert("SRKS_ee70894c79f6817fb2246d5b18fa3d55cbec4bc3f2a8d42c420a0ff0285c1804".to_string());
    set.insert("SRKS_05b81be2d8eb89faba3dae2021e94e7a806ec5eecb21647cb03b8cf6d3c74260".to_string());
    set.insert("SRKS_77973e317273af4f255a62618973e865524839b0f2a5cd7ace8edb98fdb597a1".to_string());
    set.insert("SRKS_67996e034605cf1ba791dd18a92f2da6ba8173c19c261ab1d2072d5c5b68088d".to_string());
    Mutex::new(set)
});

// Key pair
/*pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}*/

// Generate key pair from mnemonic
pub fn generate_keypair_from_mnemonic() -> (SigningKey, VerifyingKey) {
    let mnemonic = Mnemonic::generate(12).unwrap();

    println!("Mnemonic: {}", mnemonic.to_string());

    let seed = mnemonic.to_seed("");
    let seed_bytes: &[u8; 32] = seed[..32]
        .try_into()
        .expect("Error : seed must be at least 32 bytes");

    let signing_key = SigningKey::from_bytes(seed_bytes);
    let verifying_key = signing_key.verifying_key();

    (signing_key, verifying_key)
}

// Restore key pair from mnemonic
pub fn restore_keypair_from_mnemonic(
    mnemonic_phrase: &str,
) -> Result<(SigningKey, VerifyingKey), String> {
    // Parse
    let mnemonic = Mnemonic::parse(mnemonic_phrase)
        .map_err(|_| "Error: invalid mnemonic phrase".to_string())?;

    // Seed
    let seed = mnemonic.to_seed("");
    let seed_32: &[u8; 32] = seed
        .get(..32)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| "Error: seed must have at least 32 bytes".to_string())?;

    // Restore
    let signing_key = SigningKey::from_bytes(seed_32);
    let verifying_key = signing_key.verifying_key();

    Ok((signing_key, verifying_key))
}

// Sign transaction
pub fn sign_transaction(
    private_key: String,
    sender: String,
    recipient: String,
    amount: u64,
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
    let message = format!("{}:{}:{}", sender, recipient, amount);
    let signature: Signature = signing_key.sign(message.as_bytes());
    hex::encode(signature.to_bytes())
}

// Verify signature
pub fn verify_signature(public_key_hex: &str, message: &str, signature_hex: &str) -> bool {
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

// Create a new wallet
pub fn create_new_wallet(referrer_found: bool, save_private_key: &str, referrer: &str) -> Wallet {
    // Generate
    pub fn generate(referrer_found: bool, save_private_key: String, referrer: &str) -> Wallet {
        let (signing_key, verifying_key) = generate_keypair_from_mnemonic();

        let private_key_bytes = signing_key.to_bytes();
        let public_key_bytes = verifying_key.to_bytes();

        let private_key_hex = hex::encode(private_key_bytes);
        let public_key_hex = hex::encode(public_key_bytes);

        let address = format!("SRKS_{}", public_key_hex);

        // Update referrer stat
        let is_first_referrer = if referrer_found {
            match increment_file(format!("referrer_counter\\{}", referrer)) {
                Ok(current_value) => current_value <= 100,
                Err(_) => false,
            }
        } else {
            false
        };

        // Save private Key
        if !save_private_key.is_empty() {
            let owner = WalletOwner {
                public_key: public_key_hex,
                private_key: private_key_hex,
            };
            save_wallet_owner(format!("first_set\\{}", save_private_key), owner);
        }

        // Result
        Wallet {
            address: address.to_string(),
            referrer: referrer.to_string(),
            first_referrer: is_first_referrer,
        }
    }

    fn save_wallet_to_file(wallet: &Wallet, path: &str) {
        // Wallet
        let serialized = serde_json::to_string_pretty(wallet).unwrap();
        let mut file = File::create(&format!("wallets\\{}", path)).unwrap();
        file.write_all(serialized.as_bytes()).unwrap();

        // Referrer counter init
        let mut file = File::create(&format!("referrer_counter\\{}", path)).unwrap();
        file.write_all("0".as_bytes()).unwrap();
    }

    let wallet = generate(referrer_found, save_private_key.to_string(), referrer);
    save_wallet_to_file(&wallet, &wallet.address);
    return wallet;
}

// Load all wallets
pub fn load_wallets_from_folder(folder_path: &str) -> Vec<Wallet> {
    let mut wallets = Vec::new();

    let entries = fs::read_dir(folder_path).unwrap();
    for entry in entries {
        let entry = entry.unwrap();
        let path = entry.path();
        let content = fs::read_to_string(&path).unwrap();
        let wallet: Wallet = serde_json::from_str(&content).unwrap();

        wallets.push(wallet);
    }
    wallets
}

// Save wallet owner
pub fn save_wallet_owner(path: String, owner: WalletOwner) {
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .expect("Error : unable to open output file");

    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &owner).expect("Error : serializing owner");
}

// Load wallet owner
pub fn load_wallet_owner(path: String) -> WalletOwner {
    let file = File::open(path.clone()).expect("Error : WalletOwner file not found");
    let reader = BufReader::new(file);
    let wallet_owner: WalletOwner =
        serde_json::from_reader(reader).expect("Erreur : impossible read WalletOwner");
    wallet_owner
}

pub fn get_owner_address_wallet(name: String) -> String {
    let path = "first_set\\";
    return format!(
        "{}{}",
        PREFIX_ADDRESS,
        load_wallet_owner(format!("{}{}", path, name)).public_key
    );
}

pub fn get_owner_privatekey_wallet(name: String) -> String {
    let path = "first_set\\";
    return load_wallet_owner(format!("{}{}", path, name)).private_key;
}

// Find a wallet
pub fn find_wallet(wallets: &Vec<Wallet>, address: &str) -> Option<Wallet> {
    wallets.iter().find(|w| w.address == address).cloned()
}

// Check wallet
pub fn is_valid_address(address: &str) -> bool {
    address.starts_with("SRKS_")
}
