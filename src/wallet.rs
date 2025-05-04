// Dependencies
use bip39::Mnemonic;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hex;
//use rand::rngs::OsRng;
//use base64::decode;
use serde::{Deserialize, Serialize};
use sqlx::{Error, PgPool};
use std::convert::TryInto;
//use std::fs;
use std::fs::{File, OpenOptions};
//use std::io::Write;
use std::io::{BufReader, BufWriter};

// Crate
use crate::blockchain::PREFIX_ADDRESS;
//use crate::increment_file;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Wallet {
    pub address: String,
    pub referrer: Option<String>,
    pub first_referrer: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WalletOwner {
    pub public_key: String,
    pub private_key: String,
}

// Global
pub const WALLET_GENESIS: &str = "SRKS_genesis";

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
pub async fn create_new_wallet(
    referrer_found: bool,
    save_private_key: &str,
    referrer: &str,
    pg_pool: &PgPool,
) -> Wallet {
    // Keypair generate
    let (signing_key, verifying_key) = generate_keypair_from_mnemonic();

    let private_key_bytes = signing_key.to_bytes();
    let public_key_bytes = verifying_key.to_bytes();

    let private_key_hex = hex::encode(private_key_bytes);
    let public_key_hex = hex::encode(public_key_bytes);
    let address = format!("SRKS_{}", public_key_hex);

    // Check if the wallet is one of the first 100 referrals of the referrer
    let is_first_referrer = if referrer_found {
        let updated = sqlx::query!(
            r#"
            UPDATE referrer_counter
            SET counter = counter + 1
            WHERE referrer = $1
            RETURNING counter
            "#,
            address
        )
        .fetch_one(pg_pool)
        .await;

        match updated {
            Ok(row) => row.counter <= 100,
            Err(e) => {
                eprintln!("Error : update referrer_counter: {}", e);
                false
            }
        }
    } else {
        false
    };

    // If it is a owner wallet then we save the private key
    if !save_private_key.is_empty() {
        let owner = WalletOwner {
            public_key: public_key_hex,
            private_key: private_key_hex,
        };
        save_wallet_owner(format!("first_set\\{}", save_private_key), owner);
    }

    // The wallet struct
    let wallet = Wallet {
        address: address.clone(),
        referrer: (!referrer.is_empty()).then(|| referrer.to_string()),
        first_referrer: is_first_referrer,
    };

    // Insert the wallet
    if let Err(e) = sqlx::query!(
        r#"
        INSERT INTO wallets (address, referrer, first_referrer)
        VALUES ($1, $2, $3)
        "#,
        wallet.address,
        wallet.referrer,
        wallet.first_referrer
    )
    .execute(pg_pool)
    .await
    {
        eprintln!("Error : insert wallet : {}", e);
    }

    // Insert the referrer counter
    if let Err(e) = sqlx::query!(
        r#"
        INSERT INTO referrer_counter (referrer, counter)
        VALUES ($1, $2)
        "#,
        wallet.address,
        0_i32
    )
    .execute(pg_pool)
    .await
    {
        eprintln!("Error : insert referrer counter : {}", e);
    };

    // Return the wallet
    wallet
}

// Add exempt fees address
pub async fn add_exempt_fee_address(pg_pool: &PgPool, address: &str) -> Result<(), Error> {
    sqlx::query!(
        r#"
        INSERT INTO exempt_fees_addresses (address)
        VALUES ($1)
        ON CONFLICT DO NOTHING
        "#,
        address
    )
    .execute(pg_pool)
    .await?;

    Ok(())
}

// Checking if an address is exempt from fees
pub async fn is_exempt_fee_address(pg_pool: &PgPool, address: &str) -> Result<bool, Error> {
    let exists = sqlx::query_scalar!(
        r#"
        SELECT EXISTS (
            SELECT 1 FROM exempt_fees_addresses WHERE address = $1
        )
        "#,
        address
    )
    .fetch_one(pg_pool)
    .await?;

    Ok(exists.unwrap_or(false))
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
        serde_json::from_reader(reader).expect("Error : impossible read WalletOwner");
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

// Checking if wallet exists
pub async fn wallet_exists(pool: &PgPool, address: &str) -> Result<bool, Error> {
    let exists = sqlx::query_scalar!(
        r#"
        SELECT EXISTS (
            SELECT 1 FROM wallets WHERE address = $1
        )
        "#,
        address
    )
    .fetch_one(pool)
    .await?;

    Ok(exists.unwrap_or(false))
}

// Find a wallet
pub async fn find_wallet(pool: &PgPool, address: &str) -> Result<Wallet, Error> {
    let result = sqlx::query_as!(
        Wallet,
        r#"
        SELECT address, referrer, first_referrer
        FROM wallets
        WHERE address = $1
        "#,
        address
    )
    .fetch_optional(pool)
    .await?;

    Ok(result.unwrap_or(Wallet {
        address: "".to_string(),
        referrer: None,
        first_referrer: false,
    }))
}

// Check wallet
pub fn is_valid_address(address: &str) -> bool {
    address.starts_with("SRKS_")
}

// Print all wallets
pub async fn print_all_wallets(pool: &PgPool) -> Result<(), Error> {
    let wallets = sqlx::query_as!(
        Wallet,
        r#"
        SELECT address, referrer, first_referrer
        FROM wallets
        "#
    )
    .fetch_all(pool)
    .await?;

    for wallet in wallets {
        println!("{}", wallet.address);
    }

    Ok(())
}
