//! # Blockchain Module - Shariks Chain
//!
//! This module defines the core data structures and logic that represent
//! the Shariks blockchain itself. It maintains the chain of blocks,
//! enforces transaction validation rules, and handles block addition.

// Dependencies
use serde::{Deserialize, Serialize};
use serde_json;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction as QuerySync};
use uuid::Uuid;

// Crates
use crate::Utils;
use crate::encryption::*;
use crate::ledger::*;
use crate::wallet::*;

/// Defines the format of a fee rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeRule {
    pub founder_percentage: u64,
    pub treasury_percentage: u64,
    pub staking_percentage: u64,
    pub referral_percentage: u64,
}

// Globals
const MIN_AMOUNT: u64 = 1000000;
pub const NANOSRKS_PER_SRKS: u64 = 1_000_000_000;
const PERCENT_BASE: u64 = 100_000;
const FEE_RATE: u64 = 1_000;
const FEE_MAX: u64 = 100 * NANOSRKS_PER_SRKS;
pub const PREFIX_ADDRESS: &str = "SRKS_";

// Block
// -----

/// Defines the format of a block
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block {
    pub index: u64,
    pub timestamp: u128,
    pub transactions: Vec<Transaction>,
    pub previous_hash: String,
    pub hash: String,
}

impl Block {
    /// Create a new block
    pub fn new(index: u64, transactions: Vec<Transaction>, previous_hash: String) -> Self {
        let timestamp = Utils::current_timestamp();
        let mut block = Block {
            index,
            timestamp,
            transactions,
            previous_hash,
            hash: String::new(),
        };
        block.hash = block.calculate_hash();
        block
    }

    /// Calculate the hash
    pub fn calculate_hash(&self) -> String {
        let data = format!(
            "{}{}{:?}{}",
            self.index, self.timestamp, self.transactions, self.previous_hash
        );
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }

    /// Finds the index and hash of the last added block
    pub async fn get_last_block_meta(pool: &PgPool) -> Result<(u64, String), sqlx::Error> {
        let row = sqlx::query!("SELECT index, hash FROM blocks ORDER BY index DESC LIMIT 1")
            .fetch_optional(pool)
            .await?;

        if let Some(r) = row {
            Ok((r.index as u64, r.hash))
        } else {
            Ok((0, "0".to_string()))
        }
    }

    /// Saves the block in the database if the entire transaction was successful
    pub async fn save_to_db(
        block: &Block,
        query_sync: &mut QuerySync<'_, Postgres>,
    ) -> Result<(), sqlx::Error> {
        let block_json = serde_json::to_value(&block).unwrap();

        sqlx::query!(
            "INSERT INTO blocks (index, timestamp, previous_hash, hash, raw_json)
         VALUES ($1, $2, $3, $4, $5)",
            block.index as i64,
            block.timestamp as i64,
            block.previous_hash,
            block.hash,
            block_json
        )
        .execute(&mut **query_sync)
        .await?;

        Ok(())
    }
}

// Transaction
// -----------

/// Defines the format of a transaction
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Transaction {
    pub id: Uuid,
    pub sender: String,
    pub recipient: String,
    pub amount: u64,
    pub fee: u64,
    pub fee_rule: FeeRule,
    pub timestamp: u128,
    pub signature: String,
    pub referrer: String,
    pub sender_dh_public: String,
    pub recipient_dh_public: String,
    pub memo: String,
}

impl Transaction {
    // Create a transaction
    pub async fn create(
        sender: &str,
        recipient: &str,
        amount: u64,
        sender_dh_public: &str,
        recipient_dh_public: &str,
        memo: &str,
        signature: &str,
        pg_pool: &PgPool,
    ) -> Option<Transaction> {
        // Error : prefix
        if !Wallet::check_prefix(sender) {
            println!("Error : invalid sender address (must start with 'SRKS_')");
            return None;
        }
        if !Wallet::check_prefix(recipient) {
            println!("Error : invalid recipient address (must start with 'SRKS_')");
            return None;
        }

        // Error : sender is recipient
        if sender == recipient {
            println!("Error : The sender must not be the recipient");
            return None;
        }

        // Get wallets
        let sender_wallet = Wallet::find(&pg_pool, sender).await.unwrap();
        let recipient_wallet = Wallet::find(&pg_pool, recipient).await.unwrap();

        // Error : wallet not found
        if sender_wallet.address.is_empty() {
            println!("Error : sender ({}) not found", sender);
            return None;
        }
        if recipient_wallet.address.is_empty() {
            println!("Error : recipient ({}) not found", recipient);
            return None;
        }

        // Invalid amount
        if amount == 0 {
            println!("Error : Invalid amount: cannot be zero");
            return None;
        }
        if amount < MIN_AMOUNT {
            println!("Error : Amount too low: minimum required is {}", MIN_AMOUNT);
            return None;
        }

        // Error : invalid signature
        let public_key = sender_wallet.address.strip_prefix("SRKS_").unwrap_or("");
        let message = format!("{}:{}:{}:{}", sender, recipient, amount, memo);

        if !Encryption::verify_transaction(public_key, &message, signature) {
            println!("Error : invalid signature");
            return None;
        }

        // Check if bonus fee for referrer
        let sender_referrer_wallet =
            Wallet::find(&pg_pool, sender_wallet.referrer.as_deref().unwrap_or(""))
                .await
                .unwrap();

        let bonus_referrer =
            if !sender_referrer_wallet.address.is_empty() && sender_wallet.first_referrer {
                true
            } else {
                false
            };

        // Set fees
        let fee_rule = FeeRule {
            founder_percentage: if bonus_referrer {
                30_000_u64
            } else {
                40_000_u64
            },
            treasury_percentage: 30_000_u64,
            staking_percentage: 10_000_u64,
            referral_percentage: if bonus_referrer {
                30_000_u64
            } else {
                20_000_u64
            },
        };

        // Calculate fees
        let fee = if Wallet::is_exempt_fee(&pg_pool, &sender)
            .await
            .unwrap_or(false)
        {
            0
        } else {
            (amount * FEE_RATE / PERCENT_BASE).min(FEE_MAX)
        };

        let total = amount + fee;

        // Sold out
        if sender != format!("{}{}", PREFIX_ADDRESS, "genesis") {
            let balance = match Ledger::get_balance(pg_pool, sender).await {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("Error getting balance for {}: {}", sender, e);
                    return None;
                }
            };
            if balance < total {
                println!(
                    "Error : not enough tokens. current number of tokens {} : {}, required : {}",
                    sender,
                    super::to_srks(balance),
                    super::to_srks(total)
                );
                return None;
            }
        }

        println!("The transaction was successfully completed");

        Some(Transaction {
            id: Uuid::new_v4(),
            sender: sender.to_string(),
            recipient: recipient.to_string(),
            amount,
            fee,
            fee_rule,
            timestamp: Utils::current_timestamp(),
            signature: signature.to_string(),
            referrer: sender_wallet.referrer.as_deref().unwrap_or("").to_string(),
            sender_dh_public: sender_dh_public.to_string(),
            recipient_dh_public: recipient_dh_public.to_string(),
            memo: memo.to_string(),
        })
    }

    /// Saves the transaction(s) in the database if the entire transaction was successful
    pub async fn save_to_db(
        tx: &Transaction,
        block_index: u64,
        query_sync: &mut QuerySync<'_, Postgres>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query!(
            "INSERT INTO transactions (
            id, block_index,
            sender, recipient, amount, fee,
            fee_founder, fee_treasury, fee_staking, fee_referral,
            timestamp, signature, referrer,
            sender_dh_public, recipient_dh_public, memo
        ) VALUES (
            $1, $2,
            $3, $4, $5, $6,
            $7, $8, $9, $10,
            $11, $12, $13,
            $14, $15, $16
        )",
            tx.id,
            block_index as i64,
            tx.sender,
            tx.recipient,
            tx.amount as i64,
            tx.fee as i64,
            tx.fee_rule.founder_percentage as i32,
            tx.fee_rule.treasury_percentage as i32,
            tx.fee_rule.staking_percentage as i32,
            tx.fee_rule.referral_percentage as i32,
            tx.timestamp as i64,
            tx.signature,
            tx.referrer,
            tx.sender_dh_public,
            tx.recipient_dh_public,
            tx.memo
        )
        .execute(&mut **query_sync)
        .await?;

        Ok(())
    }

    /// Distribution of transaction fees
    pub fn fee_distributions(
        fee: u64,
        fee_rule: FeeRule,
        referrer_wallet: String,
    ) -> Vec<(String, u64)> {
        // Stop if no fee
        if fee == 0 {
            return vec![];
        }

        // Distribution
        let percentages = [
            fee_rule.founder_percentage,
            fee_rule.treasury_percentage,
            fee_rule.staking_percentage,
            fee_rule.referral_percentage,
        ];

        let shares = Self::split_fee_exact(fee, &percentages);

        // Get wallets
        let public_sale_address = Utils::read_from_file("owners/PUBLIC_SALE").unwrap();
        let founder_address = Utils::read_from_file("owners/FOUNDER").unwrap();
        let staking_address = Utils::read_from_file("owners/STAKING").unwrap();

        let mut result = vec![
            (founder_address.clone(), shares[0]),
            (public_sale_address, shares[1]),
            (staking_address, shares[2]),
        ];

        // Check referrer
        if !referrer_wallet.is_empty() {
            result.push((referrer_wallet, shares[3]));
        } else {
            result.push((founder_address, shares[3]));
        }

        result
    }

    /// Fee adjustment so that no tokens or nano tokens are lost
    pub fn split_fee_exact(fee: u64, percentages: &[u64]) -> Vec<u64> {
        let mut shares: Vec<u64> = percentages.iter().map(|p| fee * p / PERCENT_BASE).collect();
        let total_allocated: u64 = shares.iter().sum();
        let remainder = fee.saturating_sub(total_allocated);

        if !shares.is_empty() {
            shares[0] += remainder;
        }

        shares
    }

    /// Decrypt a transaction memo with the correct DH secret and DH public keys
    pub fn decrypt_memo(memo: &str, dh_secret: &str, dh_public: &str) -> String {
        if let Some((memo_b64, nonce_b64)) = memo.split_once(':') {
            if let (Some(secret), Some(pubkey), Some(nonce)) = (
                Encryption::hex_to_static_secret(dh_secret),
                Encryption::hex_to_xpubkey(dh_public),
                Encryption::b64_to_nonce(nonce_b64),
            ) {
                if let Some(plaintext) =
                    Encryption::decrypt_message(secret, &pubkey, memo_b64, nonce)
                {
                    plaintext
                } else {
                    eprintln!("Error : decrypt");
                    "".to_string()
                }
            } else {
                eprintln!("Error : convert key");
                "".to_string()
            }
        } else {
            eprintln!("Error : separator");
            "".to_string()
        }
    }
}

/// Checking that the blockchain does not already exist
pub async fn is_empty(pool: &PgPool) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;

    // Check if block exists
    let count = sqlx::query_scalar!("SELECT COUNT(*) FROM blocks")
        .fetch_one(&mut *tx)
        .await?;

    // Check genesis status
    let genesis_done: bool =
        sqlx::query_scalar!("SELECT genesis_done FROM system_status WHERE id = 1")
            .fetch_one(&mut *tx)
            .await?;

    // Lock to avoid concurrent init
    sqlx::query!("LOCK TABLE blocks IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    Ok(count.map_or(false, |n| n == 0) && !genesis_done)
}

/// Load all blocks in json from the database
pub async fn load_blocks_from_db(pg_pool: &PgPool) -> Result<Vec<Block>, sqlx::Error> {
    let rows = sqlx::query!("SELECT raw_json FROM blocks ORDER BY index ASC")
        .fetch_all(pg_pool)
        .await?;

    let mut blocks = Vec::new();
    for row in rows {
        let block: Block = serde_json::from_value(row.raw_json).unwrap();
        blocks.push(block);
    }

    Ok(blocks)
}

/// Convert SRKS units to nanosrks
pub fn to_nanosrks(srks: f64) -> u64 {
    (srks * NANOSRKS_PER_SRKS as f64).round() as u64
}

/// Convert nanosrks to SRKS units
pub fn to_srks(nanosrks: u64) -> f64 {
    nanosrks as f64 / NANOSRKS_PER_SRKS as f64
}
