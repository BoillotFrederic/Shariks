// Dependencies
use sqlx::PgPool;
use uuid::Uuid;

// Crates
use crate::Utils;
use crate::blockchain;
use crate::blockchain::*;
use crate::encryption::*;
use crate::ledger;
use crate::ledger::*;
use crate::wallet::*;

// Structures
pub struct Genesis;

// Genesis class
impl Genesis {
    // Start genesis
    pub async fn start(
        blockchain: &mut Vec<blockchain::Block>,
        ledger: &mut ledger::LedgerMap,
        pg_pool: &PgPool,
    ) {
        // Public sale
        let public_sale_wallet = Wallet::new(false, &"PUBLIC_SALE".to_string(), "", &pg_pool).await;
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
        Self::distribute(ledger, blockchain, &pg_pool).await;

        // First block chain save
        blockchain::save(&blockchain);
    }

    // Distribute tokens
    async fn distribute(
        ledger: &mut ledger::LedgerMap,
        blockchain: &mut blockchain::Blockchain,
        pg_pool: &PgPool,
    ) {
        // Public sale
        let public_sale_address = Wallet::get_owner_address("PUBLIC_SALE".to_string());
        let public_sale_private_key = Wallet::get_owner_privatekey("PUBLIC_SALE".to_string());
        let public_sale_wallet = Wallet::find(&pg_pool, &public_sale_address).await.unwrap();

        if let Err(e) = Wallet::add_exempt_fee(&pg_pool, &public_sale_wallet.address).await {
            eprintln!("Error : add exempt_fees_address : {}", e);
        }

        // Wallets to be created
        let wallet_names = vec!["FOUNDER", "SPONSORSHIP", "TREASURY", "STAKING"];

        for wallet_name in wallet_names.iter() {
            let wallet = Wallet::new(false, wallet_name, "", &pg_pool).await;
            if let Err(e) = Wallet::add_exempt_fee(&pg_pool, &wallet.address).await {
                eprintln!("Error : add exempt_fees_address : {}", e);
            }
        }

        let distribution = vec![
            (
                Wallet::get_owner_address("SPONSORSHIP".to_string()),
                10_000_000 * NANOSRKS_PER_SRKS,
            ),
            (
                Wallet::get_owner_address("TREASURY".to_string()),
                10_000_000 * NANOSRKS_PER_SRKS,
            ),
        ];

        let mut transactions = Vec::new();

        for (recipient, amount) in distribution {
            // Signature
            let signature = Encryption::sign_transaction(
                public_sale_private_key.to_string(),
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
    }
}
