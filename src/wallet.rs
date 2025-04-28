// Dependencies
use bip39::Mnemonic;
use ed25519_dalek::{SigningKey, VerifyingKey};
use hex;
use once_cell::sync::Lazy;
//use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
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
pub static EXEMPT_FEES_ADDRESSES: Lazy<Mutex<HashSet<String>>> =
    Lazy::new(|| Mutex::new(HashSet::new()));

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
pub fn restore_keypair_from_mnemonic(mnemonic_phrase: &str) -> (SigningKey, VerifyingKey) {
    let mnemonic = Mnemonic::parse(mnemonic_phrase).expect("Error: invalid mnemonic phrase");

    let seed = mnemonic.to_seed("");
    let seed_32: &[u8; 32] = seed
        .get(..32)
        .and_then(|slice| slice.try_into().ok())
        .expect("Error: seed must have at least 32 bytes");

    let signing_key = SigningKey::from_bytes(seed_32);
    let verifying_key = signing_key.verifying_key();

    (signing_key, verifying_key)
}

pub fn create_new_wallet(referrer_found: bool, save_private_key: &str, referrer: &str) -> Wallet {
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
        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            let content = fs::read_to_string(path).unwrap();
            let wallet: Wallet = serde_json::from_str(&content).unwrap();
            wallets.push(wallet);
        }
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

// Find a wallet
pub fn find_wallet(wallets: &Vec<Wallet>, address: &str) -> Option<Wallet> {
    wallets.iter().find(|w| w.address == address).cloned()
}

// Check wallet
pub fn is_valid_address(address: &str) -> bool {
    address.starts_with("SRKS_")
}
