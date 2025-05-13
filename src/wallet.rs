// Dependencies
use hex;
use serde::{Deserialize, Serialize};
use sqlx::{Error, PgPool};

// Crate
use crate::blockchain;
use crate::encryption::*;
use crate::utils::*;
use crate::vault;
use crate::vault::*;

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
        owner_wallet_name: &str,
        referrer: &str,
        passphrase: &str,
        pg_pool: &PgPool,
    ) -> Wallet {
        // Keypair generate
        let (phrase, signing_key, verifying_key, dh_secret, dh_public) =
            Encryption::generate_full_keypair_from_mnemonic(passphrase);

        let private_key_bytes = signing_key.to_bytes();
        let public_key_bytes = verifying_key.to_bytes();

        let private_key_hex = hex::encode(private_key_bytes);
        let public_key_hex = hex::encode(public_key_bytes);
        let dh_public = hex::encode(dh_public.as_bytes());
        let address = format!("{}{}", blockchain::PREFIX_ADDRESS, public_key_hex);

        println!("Mnemonic : {}", phrase);

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
        if !owner_wallet_name.is_empty() {
            let owner_secret = vault::WalletSecret {
                mnemonic: phrase.clone(),
                passphrase: passphrase.to_string(),
                public_key: public_key_hex.clone(),
                private_key: private_key_hex.clone(),
                dh_public: hex::encode(dh_public.as_bytes()),
                dh_secret: hex::encode(dh_secret.to_bytes()),
            };

            match VaultService::set_owner_secret(owner_wallet_name, owner_secret).await {
                Ok(()) => {
                    println!("Secret : {} has been set", owner_wallet_name);
                }
                Err(err) => eprintln!("Error : Vault : {}", err),
            }

            Utils::write_to_file(&format!("owners\\{}", owner_wallet_name), &address).unwrap();
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

    // Add prefix
    pub fn add_prefix(public_key: &str) -> String {
        return format!("{}{}", blockchain::PREFIX_ADDRESS, public_key);
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
