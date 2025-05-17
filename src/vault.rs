//! # Vault Module - Shariks Chain
//!
//! The `vault` module is responsible for managing and securing system-level wallet keys
//! and sensitive data such as the private keys of genesis or operational wallets.

// Dependencies
use serde::{Deserialize, Serialize};
use std::env;
use std::error::Error;
use vaultrs::auth::approle;
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};
use vaultrs::kv2;

/// Defines the format of a WalletSecret
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalletSecret {
    pub mnemonic: String,
    pub passphrase: String,
    pub public_key: String,
    pub private_key: String,
    pub dh_public: String,
    pub dh_secret: String,
}

// Vault service
// -------------

pub struct VaultService;

impl VaultService {
    /// Authentication with AppRole and Vault
    async fn login_with_approle() -> Result<VaultClient, Box<dyn std::error::Error>> {
        let addr = env::var("VAULT_ADDR")?;
        let role_id = env::var("VAULT_ROLE_ID")?;
        let secret_id = env::var("VAULT_SECRET_ID")?;

        let client = VaultClient::new(
            VaultClientSettingsBuilder::default()
                .address(addr.clone())
                .build()?,
        )?;

        let login = approle::login(&client, "approle", &role_id, &secret_id).await?;
        let token = login.client_token;

        let authed_client = VaultClient::new(
            VaultClientSettingsBuilder::default()
                .address(addr)
                .token(token)
                .build()?,
        )?;

        Ok(authed_client)
    }

    /// Write a secret owner wallet
    pub async fn set_owner_secret(
        wallet_name: &str,
        wallet: WalletSecret,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let client = Self::login_with_approle().await?;
        let secret_location = format!("shariks_wallets/{}", wallet_name);
        kv2::set(&client, "secret", &secret_location, &wallet).await?;

        Ok(())
    }

    /// Read a secret owner wallet
    pub async fn get_owner_secret(wallet_name: &str) -> Result<WalletSecret, Box<dyn Error>> {
        // Read secret
        let client = Self::login_with_approle().await?;
        let path = format!("shariks_wallets/{}", wallet_name);
        let result = kv2::read::<WalletSecret>(&client, "secret", &path).await;

        // Default
        let secret = result.unwrap_or(WalletSecret {
            mnemonic: "".to_string(),
            passphrase: "".to_string(),
            public_key: "".to_string(),
            private_key: "".to_string(),
            dh_public: "".to_string(),
            dh_secret: "".to_string(),
        });

        Ok(secret)
    }
}
