//! # Wallet Module - Shariks Chain
//!
//! The `wallet` module defines the structure, creation, and verification
//! logic for wallets in the Shariks blockchain.

// Dependencies
use chrono::{DateTime, Duration, Utc};
use hex;
use serde::{Deserialize, Serialize};
use sqlx::{Error, PgPool};

// Crate
use crate::blockchain;
use crate::encryption::*;
use crate::log::*;
use crate::utils::*;
use crate::vault;
use crate::vault::*;

// Types
type DynError = Box<dyn std::error::Error>;

/// Defines the format of a wallet owner
#[derive(Serialize, Deserialize, Debug)]
pub struct WalletOwner {
    pub public_key: String,
    pub private_key: String,
}

// Global
pub const WALLET_GENESIS: &str = "SRKS_genesis";

// Wallet
// ------

/// Defines the format of a wallet
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Wallet {
    pub address: String,
    pub referrer: Option<String>,
    pub first_referrer: bool,
    pub staking_available: bool,
    pub last_login: DateTime<Utc>,
}

impl Wallet {
    /// Create a new wallet
    pub async fn new(
        referrer_found: bool,
        owner_wallet_name: &str,
        referrer: &str,
        passphrase: &str,
        exempt_fee: bool,
        staking_available: bool,
        pg_pool: &PgPool,
    ) -> Result<Wallet, DynError> {
        // Keypair generate
        let (phrase, signing_key, verifying_key, dh_secret, dh_public) =
            match Encryption::generate_full_keypair_from_mnemonic(passphrase) {
                Ok(keys) => keys,
                Err(e) => {
                    Log::error("Wallet", "new", "Failed to generate keys", &e.to_string());
                    return Err(e);
                }
            };

        let private_key_bytes = signing_key.to_bytes();
        let public_key_bytes = verifying_key.to_bytes();

        let private_key_hex = hex::encode(private_key_bytes);
        let public_key_hex = hex::encode(public_key_bytes);
        let dh_public = hex::encode(dh_public.as_bytes());
        let address = format!("{}{}", blockchain::PREFIX_ADDRESS, public_key_hex);

        println!("Mnemonic : {}", phrase);

        // Check if the wallet is one of the first 100 referrals of the referrer
        let is_first_referrer = if referrer_found {
            let updated = Utils::with_timeout(
                sqlx::query!(
                    r#"
                    UPDATE core.wallets
                    SET referrer_count = referrer_count + 1
                    WHERE address = $1
                    RETURNING referrer_count
                    "#,
                    referrer
                )
                .fetch_one(pg_pool),
                30,
            )
            .await;

            match updated {
                Ok(row) => row.referrer_count <= 100,
                Err(e) => {
                    Log::error("Wallet", "new", "Update referrer_count failed", e);
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
                dh_public: dh_public.clone(),
                dh_secret: hex::encode(dh_secret.to_bytes()),
            };

            match VaultService::set_owner_secret(owner_wallet_name, owner_secret).await {
                Ok(()) => {
                    println!("Secret : {} has been set", owner_wallet_name);
                }
                Err(e) => Log::error("Wallet", "new", "Write secret failed", e),
            }

            Utils::write_to_file(&format!("owners\\{}", owner_wallet_name), &address).map_err(
                |e| {
                    Log::error(
                        "Wallet",
                        "new",
                        "Failed to write wallet address to file",
                        &e.to_string(),
                    );
                    e
                },
            )?;
        }

        // The wallet struct
        let wallet = Wallet {
            address: address.clone(),
            referrer: (!referrer.is_empty()).then(|| referrer.to_string()),
            first_referrer: is_first_referrer,
            staking_available: true,
            last_login: Utc::now(),
        };

        // Insert the wallet
        if let Err(e) = Utils::with_timeout(sqlx::query!(
            r#"
            INSERT INTO core.wallets (address, dh_public, referrer, first_referrer, exempt_fee, staking_available)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            wallet.address,
            dh_public,
            wallet.referrer,
            wallet.first_referrer,
            exempt_fee,
            staking_available
        )
        .execute(pg_pool), 30)
        .await
        {
            Log::error("Wallet", "new", "Insert wallet failed", e);
        }

        // Return the wallet
        Ok(wallet)
    }

    /// Find a wallet
    pub async fn find(pool: &PgPool, address: &str) -> Result<Wallet, Error> {
        let result = Utils::with_timeout(
            sqlx::query_as!(
                Wallet,
                r#"
                SELECT
                    address,
                    referrer,
                    first_referrer,
                    staking_available,
                    last_login as "last_login: DateTime<chrono::Utc>"
                FROM core.wallets
                WHERE address = $1
                "#,
                address
            )
            .fetch_optional(pool),
            30,
        )
        .await?;

        Ok(result.unwrap_or(Wallet {
            address: "".to_string(),
            referrer: None,
            first_referrer: false,
            staking_available: true,
            last_login: Utc::now(),
        }))
    }

    /// Checking if wallet exists
    pub async fn exists(pool: &PgPool, address: &str) -> Result<bool, Error> {
        let exists = Utils::with_timeout(
            sqlx::query_scalar!(
                r#"
                SELECT EXISTS (
                SELECT 1 FROM core.wallets WHERE address = $1
            )
            "#,
                address
            )
            .fetch_one(pool),
            30,
        )
        .await?;

        Ok(exists.unwrap_or(false))
    }

    /// Check if a wallet has been inactive for 1 year
    pub fn is_inactive(wallet: Wallet) -> bool {
        let limit = Utc::now() - Duration::days(365);
        let last_login = wallet.last_login;
        last_login < limit
    }

    /// Updates the last wallet connection
    #[allow(unused)]
    pub async fn update_last_login(pool: &PgPool, address: &str) -> Result<(), sqlx::Error> {
        Utils::with_timeout(
            sqlx::query!(
                r#"
                UPDATE core.wallets
                SET last_login = now()
                WHERE address = $1
                "#,
                address
            )
            .execute(pool),
            30,
        )
        .await?;

        Ok(())
    }

    /// Check if the address starts with the correct prefix
    pub fn check_prefix(address: &str) -> bool {
        address.starts_with(blockchain::PREFIX_ADDRESS)
    }

    /// Checking if an address is exempt from fees
    pub async fn is_exempt_fee(pg_pool: &PgPool, address: &str) -> Result<bool, Error> {
        let exists = Utils::with_timeout(
            sqlx::query_scalar!(
                r#"
                SELECT EXISTS (
                    SELECT 1 FROM core.wallets WHERE address = $1 and exempt_fee = true
                )
                "#,
                address
            )
            .fetch_one(pg_pool),
            30,
        )
        .await?;

        Ok(exists.unwrap_or(false))
    }

    /// Adds the prefix to a public key
    pub fn add_prefix(public_key: &str) -> String {
        return format!("{}{}", blockchain::PREFIX_ADDRESS, public_key);
    }

    /// Print all created wallets
    pub async fn print_all(pool: &PgPool) -> Result<(), Error> {
        let wallets = Utils::with_timeout(
            sqlx::query_as!(
                Wallet,
                r#"
                SELECT address, referrer, first_referrer, staking_available,
                last_login as "last_login: DateTime<chrono::Utc>"
                FROM core.wallets
                "#
            )
            .fetch_all(pool),
            30,
        )
        .await?;

        for wallet in wallets {
            println!("{}", wallet.address);
        }

        Ok(())
    }
}
