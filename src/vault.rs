// Dependencies
use serde::{Deserialize, Serialize};
use std::env;
use std::error::Error;
use vaultrs::auth::approle;
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
    // Auth
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

    // Set owner
    pub async fn set_owner_secret(
        wallet_name: &str,
        wallet: WalletSecret,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let client = Self::login_with_approle().await?;
        let secret_location = format!("shariks_wallets/{}", wallet_name);
        kv2::set(&client, "secret", &secret_location, &wallet).await?;

        Ok(())
    }

    // Get owner
    pub async fn get_owner_secret(wallet_name: &str) -> Result<WalletSecret, Box<dyn Error>> {
        // Read secret
        let client = Self::login_with_approle().await?;
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
