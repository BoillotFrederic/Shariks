// Dependencies
use sqlx::PgPool;
use std::env;
use uuid::Uuid;

// Crates
use crate::Utils;
use crate::blockchain;
use crate::blockchain::*;
use crate::encryption::*;
use crate::ledger;
use crate::ledger::*;
use crate::vault::*;
use crate::wallet::*;

// Structures
pub struct Genesis;

// Genesis
// -------

impl Genesis {
    // Start genesis
    pub async fn start(
        blockchain: &mut Vec<blockchain::Block>,
        ledger: &mut ledger::LedgerMap,
        pg_pool: &PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Public sale
        let genesis_passphrase = env::var("GENESIS_PASSPHRASE")?;
        let public_sale_wallet = Wallet::new(
            false,
            &"PUBLIC_SALE".to_string(),
            "",
            &genesis_passphrase,
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

        let genesis_block = blockchain::Block::new(0, vec![genesis_tx], "0".to_string());
        blockchain.push(genesis_block.clone());
        Ledger::update_with_block(ledger, &genesis_block);

        // Transaction of distribution initial
        Self::distribute(ledger, blockchain, &pg_pool).await?;

        // First block chain save
        blockchain::save(&blockchain);

        Ok(())
    }

    // Distribute tokens
    async fn distribute(
        ledger: &mut ledger::LedgerMap,
        blockchain: &mut blockchain::Blockchain,
        pg_pool: &PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Public sale
        let public_sale_secret = VaultService::get_owner_secret(&"PUBLIC_SALE".to_string()).await?;
        let public_sale_address = Wallet::add_prefix(&public_sale_secret.public_key);

        if let Err(e) = Wallet::add_exempt_fee(&pg_pool, &public_sale_address).await {
            eprintln!("Error : add exempt_fees_address : {}", e);
        }

        // Wallets to be created
        let wallet_names = vec!["FOUNDER", "SPONSORSHIP", "TREASURY", "STAKING"];
        let genesis_passphrase = env::var("GENESIS_PASSPHRASE")?;
        let mut wallet_addresses: Vec<String> = Vec::new();
        for wallet_name in wallet_names.iter() {
            let wallet = Wallet::new(false, wallet_name, "", &genesis_passphrase, &pg_pool).await;
            wallet_addresses.push(wallet.address.clone());
            if let Err(e) = Wallet::add_exempt_fee(&pg_pool, &wallet.address).await {
                eprintln!("Error : add exempt_fees_address : {}", e);
            }
        }

        let distribution = vec![
            (&wallet_addresses[1], 10_000_000 * NANOSRKS_PER_SRKS),
            (&wallet_addresses[2], 10_000_000 * NANOSRKS_PER_SRKS),
        ];

        let mut transactions = Vec::new();

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
                ledger,
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
                Ledger::apply_transaction(ledger, &tx);
                transactions.push(tx);
            }
        }

        // Create a new block
        if !transactions.is_empty() {
            let previous_block = blockchain.last().unwrap();
            let index = previous_block.index + 1;
            let timestamp = Utils::current_timestamp();
            let previous_hash = previous_block.hash.clone();

            let block = Block {
                index,
                timestamp,
                previous_hash,
                transactions: transactions.clone(),
                hash: String::new(),
            };

            let mut finalized_block = block;
            finalized_block.hash = finalized_block.calculate_hash();

            blockchain.push(finalized_block);
        }

        Ok(())
    }
}
