//! # Genesis Module - Shariks Chain
//!
//! This module initializes the Shariks blockchain with a predefined state at genesis.
//! It sets up the initial distribution of tokens and system wallets that form
//! the foundation of the network.
//!
//! ## Key Features:
//!
//! - **Token Supply Initialization**
//!   - Defines a fixed total supply of **100 million SRKS** tokens.
//!
//! - **Genesis Allocation**
//!   - **80%** to the `PUBLIC_SALE` wallet (for public distribution).
//!   - **10%** to the `SPONSORSHIP` wallet (reserve in case of malfunction).
//!   - **10%** to the `TREASURY` wallet (reserve in case of malfunction).
//!
//! - **System Wallets Created at Genesis**
//!   - `FOUNDER` - Infrastructure and development.
//!   - `TREASURY` - Reserve in case of malfunction.
//!   - `STAKING` - Redistributes them monthly to holders.
//!   - `SPONSORSHIP` - Reserve in case of malfunction.
//!   - `PUBLIC_SALE` - Intended for public sale.

// Dependencies
use sqlx::PgPool;
use std::env;
use uuid::Uuid;

// Crates
use crate::Utils;
use crate::blockchain;
use crate::blockchain::*;
use crate::encryption::*;
use crate::ledger::*;
use crate::vault::*;
use crate::wallet::*;

// Genesis
// -------

pub struct Genesis;

impl Genesis {
    /// Beginning of Genesis
    pub async fn start(pg_pool: &PgPool) -> Result<(), Box<dyn std::error::Error>> {
        // Public sale
        let genesis_passphrase = env::var("GENESIS_PASSPHRASE")?;
        let public_sale_wallet = Wallet::new(
            false,
            &"PUBLIC_SALE".to_string(),
            "",
            &genesis_passphrase,
            true,
            false,
            &pg_pool,
        )
        .await;
        let memo = "GENESIS";

        // Transaction GENESIS
        let fee_rule = blockchain::FeeRule {
            founder_percentage: 0,
            treasury_percentage: 0,
            staking_percentage: 0,
            referral_percentage: 0,
        };

        let genesis_tx = blockchain::Transaction {
            id: Uuid::new_v4(),
            sender: WALLET_GENESIS.to_string(),
            recipient: public_sale_wallet.address,
            amount: 100_000_000_000_000_000,
            fee: 0,
            fee_rule,
            timestamp: Utils::current_timestamp(),
            referrer: "".to_string(),
            signature: "".to_string(),
            sender_dh_public: "".to_string(),
            recipient_dh_public: "".to_string(),
            memo: memo.to_string(),
        };

        let genesis_block = blockchain::Block::new(0, vec![genesis_tx.clone()], "0".to_string());
        let mut query_sync = pg_pool.begin().await?;

        let result = {
            blockchain::Block::save_to_db(&genesis_block, &mut query_sync).await?;
            blockchain::Transaction::save_to_db(&genesis_tx, genesis_block.index, &mut query_sync)
                .await?;
            Ledger::apply_transaction(&genesis_tx, &mut query_sync).await?;

            // Genesis done
            Utils::with_timeout(
                sqlx::query!(
                    r#"
                    UPDATE core.system_status
                    SET genesis_done = TRUE, last_updated = now()
                    WHERE id = 1
                    "#
                )
                .execute(pg_pool),
                30,
            )
            .await?;
            Ok::<(), Box<dyn std::error::Error>>(())
        };

        match result {
            Ok(_) => {
                query_sync.commit().await?;

                // Transaction of distribution initial
                Self::distribute(&pg_pool).await?;
            }
            Err(e) => {
                query_sync.rollback().await.ok();
                return Err(e);
            }
        }

        Ok(())
    }

    /// Initial distribution of tokens
    async fn distribute(pg_pool: &PgPool) -> Result<(), Box<dyn std::error::Error>> {
        // Public sale
        let public_sale_secret = VaultService::get_owner_secret(&"PUBLIC_SALE".to_string()).await?;
        let public_sale_address = Wallet::add_prefix(&public_sale_secret.public_key);

        // Wallets to be created
        let wallet_names = vec!["FOUNDER", "SPONSORSHIP", "TREASURY", "STAKING"];
        let genesis_passphrase = env::var("GENESIS_PASSPHRASE")?;
        let mut wallet_addresses: Vec<String> = Vec::new();

        for wallet_name in wallet_names.iter() {
            let wallet = Wallet::new(
                false,
                wallet_name,
                "",
                &genesis_passphrase,
                true,
                false,
                &pg_pool,
            )
            .await;
            wallet_addresses.push(wallet.address.clone());
        }

        let distribution = vec![
            (&wallet_addresses[1], 10_000_000 * NANOSRKS_PER_SRKS),
            (&wallet_addresses[2], 10_000_000 * NANOSRKS_PER_SRKS),
        ];

        let mut query_sync = pg_pool.begin().await?;
        let mut transactions = Vec::new();

        let result = {
            for (recipient, amount) in distribution {
                // Signature
                let signature = Encryption::sign_transaction(
                    public_sale_secret.private_key.clone(),
                    public_sale_address.clone(),
                    recipient.clone(),
                    amount,
                    "Initial distribution".to_string(),
                );

                // Transaction
                if let Some(tx) = blockchain::Transaction::create(
                    &public_sale_address,
                    &recipient,
                    amount,
                    "",
                    "",
                    "Initial distribution",
                    &signature,
                    &pg_pool,
                )
                .await
                {
                    Ledger::apply_transaction(&tx, &mut query_sync).await?;
                    transactions.push(tx);
                }
            }

            // Create a new block
            if !transactions.is_empty() {
                let (last_index, last_hash) =
                    blockchain::Block::get_last_block_meta(&pg_pool).await?;
                let index = last_index + 1;
                let timestamp = Utils::current_timestamp();
                let previous_hash = last_hash;

                let block = Block {
                    index,
                    timestamp,
                    previous_hash,
                    transactions: transactions.clone(),
                    hash: String::new(),
                };

                let mut finalized_block = block;
                finalized_block.hash = finalized_block.calculate_hash();

                blockchain::Block::save_to_db(&finalized_block, &mut query_sync).await?;
                for tx in &finalized_block.transactions {
                    blockchain::Transaction::save_to_db(tx, finalized_block.index, &mut query_sync)
                        .await?;
                }
            }

            Ok::<(), Box<dyn std::error::Error>>(())
        };

        match result {
            Ok(_) => {
                query_sync.commit().await?;
                Ok(())
            }
            Err(e) => {
                query_sync.rollback().await.ok();
                Err(e)
            }
        }
    }
}
