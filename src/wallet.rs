// Dependencies
use hex;
use serde::{Deserialize, Serialize};
use sqlx::{Error, PgPool};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter};

// Crate
use crate::blockchain;
use crate::blockchain::*;
use crate::encryption::*;

#[derive(Serialize, Deserialize, Debug)]
pub struct WalletOwner {
    pub public_key: String,
    pub private_key: String,
}

// Global
pub const WALLET_GENESIS: &str = "SRKS_genesis";

// Wallet
// ------

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Wallet {
    pub address: String,
    pub referrer: Option<String>,
    pub first_referrer: bool,
}

impl Wallet {
    // Create a new wallet
    pub async fn new(
        referrer_found: bool,
        save_private_key: &str,
        referrer: &str,
        pg_pool: &PgPool,
    ) -> Wallet {
        // Keypair generate
        let (phrase, signing_key, verifying_key, dh_secret, dh_public) =
            Encryption::generate_full_keypair_from_mnemonic();

        let private_key_bytes = signing_key.to_bytes();
        let public_key_bytes = verifying_key.to_bytes();

        let private_key_hex = hex::encode(private_key_bytes);
        let public_key_hex = hex::encode(public_key_bytes);
        let dh_public = hex::encode(dh_public.as_bytes());
        let address = format!("{}{}", blockchain::PREFIX_ADDRESS, public_key_hex);

        println!("Mnemonic : {}", phrase);
        println!("dh_secret : {}", hex::encode(dh_secret.to_bytes()));

        // Check if the wallet is one of the first 100 referrals of the referrer
        let is_first_referrer = if referrer_found {
            let updated = sqlx::query!(
                r#"
                UPDATE referrer_counter
                SET counter = counter + 1
                WHERE referrer = $1
                RETURNING counter
                "#,
                referrer
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
            Self::save_owner(format!("first_set\\{}", save_private_key), owner);
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
            INSERT INTO wallets (address, dh_public, referrer, first_referrer)
            VALUES ($1, $2, $3, $4)
            "#,
            wallet.address,
            dh_public,
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

    // Find a wallet
    pub async fn find(pool: &PgPool, address: &str) -> Result<Wallet, Error> {
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

    // Checking if wallet exists
    pub async fn exists(pool: &PgPool, address: &str) -> Result<bool, Error> {
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

    // Check wallet
    pub fn check_prefix(address: &str) -> bool {
        address.starts_with(blockchain::PREFIX_ADDRESS)
    }

    // Add exempt fees address
    pub async fn add_exempt_fee(pg_pool: &PgPool, address: &str) -> Result<(), Error> {
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
    pub async fn is_exempt_fee(pg_pool: &PgPool, address: &str) -> Result<bool, Error> {
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
    pub fn save_owner(path: String, owner: WalletOwner) {
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
    pub fn load_owner(path: String) -> WalletOwner {
        let file = File::open(path.clone()).expect("Error : WalletOwner file not found");
        let reader = BufReader::new(file);
        let wallet_owner: WalletOwner =
            serde_json::from_reader(reader).expect("Error : impossible read WalletOwner");
        wallet_owner
    }

    pub fn get_owner_address(name: String) -> String {
        let path = "first_set\\";
        return format!(
            "{}{}",
            PREFIX_ADDRESS,
            Self::load_owner(format!("{}{}", path, name)).public_key
        );
    }

    pub fn get_owner_privatekey(name: String) -> String {
        let path = "first_set\\";
        return Self::load_owner(format!("{}{}", path, name)).private_key;
    }

    // Print all wallets
    pub async fn print_all(pool: &PgPool) -> Result<(), Error> {
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
}
