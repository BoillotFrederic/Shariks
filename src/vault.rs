// Dependencies
use serde::{Deserialize, Serialize};
use std::env;
use std::error::Error;
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};
use vaultrs::kv2;

// Structures
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalletSecret {
    pub mnemonic: String,
    pub public_key: String,
    pub private_key: String,
    pub dh_public: String,
    pub dh_secret: String,
}

// Vault service
// -------------

pub struct VaultService;
impl VaultService {
    // Set owner
    pub async fn set_owner_secret(
        wallet_name: &str,
        wallet: WalletSecret,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Connection
        let vault_addr = env::var("VAULT_ADDR")?;
        let vault_token = env::var("VAULT_TOKEN")?;

        let client = VaultClient::new(
            VaultClientSettingsBuilder::default()
                .address(vault_addr)
                .token(vault_token)
                .build()?,
        )?;

        // Write
        let secret_location = format!("shariks_wallets/{}", wallet_name);
        kv2::set(&client, "secret", &secret_location, &wallet).await?;

        Ok(())
    }

    // Get owner
    pub async fn get_owner_secret(wallet_name: &str) -> Result<WalletSecret, Box<dyn Error>> {
        // Connection
        let vault_addr = env::var("VAULT_ADDR")?;
        let vault_token = env::var("VAULT_TOKEN")?;

        let client = VaultClient::new(
            VaultClientSettingsBuilder::default()
                .address(vault_addr)
                .token(vault_token)
                .build()?,
        )?;

        // Read secret
        let path = format!("shariks_wallets/{}", wallet_name);
        let result = kv2::read::<WalletSecret>(&client, "secret", &path).await;

        // Default
        let secret = result.unwrap_or(WalletSecret {
            mnemonic: "".to_string(),
            public_key: "".to_string(),
            private_key: "".to_string(),
            dh_public: "".to_string(),
            dh_secret: "".to_string(),
        });

        Ok(secret)
    }
}
