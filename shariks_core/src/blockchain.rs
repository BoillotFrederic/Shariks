//! # Blockchain Module - Shariks Chain
//!
//! This module defines the core data structures and logic that represent
//! the Shariks blockchain itself. It maintains the chain of blocks,
//! enforces transaction validation rules, and handles block addition.

// Dependencies
use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction as QuerySync};
use std::fs::OpenOptions;
use std::io::Write;
use uuid::Uuid;

// Crates
use crate::encryption::*;
use crate::ledger::*;
use crate::log::*;
use crate::utils::Utils;
use crate::vault::*;
use crate::wallet::*;

// Types
type DynError = Box<dyn std::error::Error>;

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
pub const PERCENT_BASE: u64 = 100_000;
pub const FEE_RATE: u64 = 1_000;
pub const FEE_MAX: u64 = 100 * NANOSRKS_PER_SRKS;
pub const PREFIX_ADDRESS: &str = "SRKS_";
const FOUNDER_INDEX: usize = 0;
const TREASURY_INDEX: usize = 1;
const STAKING_INDEX: usize = 2;
const REFERRAL_INDEX: usize = 3;

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
        let row = Utils::with_timeout(
            sqlx::query!("SELECT index, hash FROM core.blocks ORDER BY index DESC LIMIT 1")
                .fetch_optional(pool),
            30,
        )
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
        let block_json = serde_json::to_value(&block).map_err(|e| {
            Log::error(
                "Blockchain::Blocks",
                "save_to_db",
                "Block serialization",
                e.to_string(),
            );
            sqlx::Error::Protocol(e.to_string().into())
        })?;

        Utils::with_timeout(
            sqlx::query!(
                "INSERT INTO core.blocks (index, timestamp, previous_hash, hash, raw_json)
         VALUES ($1, $2, $3, $4, $5)",
                block.index as i64,
                block.timestamp as i64,
                block.previous_hash,
                block.hash,
                block_json
            )
            .execute(&mut **query_sync),
            90,
        )
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
#[derive(sqlx::FromRow, Debug, Serialize)]
pub struct GetTransaction {
    pub sender: String,
    pub recipient: String,
    pub amount_srks: Option<f64>,
    pub timestamp: i64,
    pub sender_dh_public: Option<String>,
    pub recipient_dh_public: Option<String>,
    pub memo: Option<String>,
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
        message: &str,
        pg_pool: &PgPool,
    ) -> Option<Transaction> {
        // Error : prefix
        if !Wallet::check_prefix(sender) {
            Log::error_msg(
                "Blockchain::Transaction",
                "create",
                "Sender address must start with 'SRKS_",
            );
            return None;
        }
        if !Wallet::check_prefix(recipient) {
            Log::error_msg(
                "Blockchain::Transaction",
                "create",
                "Recipient address must start with 'SRKS_",
            );
            return None;
        }

        // Error : sender is recipient
        if sender == recipient {
            Log::error_msg(
                "Blockchain::Transaction",
                "create",
                "The sender must not be the recipient",
            );
            return None;
        }

        // Get wallets
        let sender_wallet = match Wallet::find(&pg_pool, sender).await {
            Ok(wallet) => wallet,
            Err(e) => {
                Log::error("Blockchain::Transaction", "create", "Find sender error", e);
                return None;
            }
        };

        let recipient_wallet = match Wallet::find(&pg_pool, recipient).await {
            Ok(wallet) => wallet,
            Err(e) => {
                Log::error(
                    "Blockchain::Transaction",
                    "create",
                    "Find recipient error",
                    e,
                );
                return None;
            }
        };

        // Error : wallet not found
        if sender_wallet.address.is_empty() {
            Log::error_msg("Blockchain::Transaction", "create", "Sender not found");
            return None;
        }
        if recipient_wallet.address.is_empty() {
            Log::error_msg("Blockchain::Transaction", "create", "Recipient not found");
            return None;
        }

        // Invalid amount
        if amount == 0 {
            Log::error_msg("Blockchain::Transaction", "create", "Amount cannot be zero");
            return None;
        }
        if amount < MIN_AMOUNT {
            Log::error_msg(
                "Blockchain::Transaction",
                "create",
                &format!("Amount minimum required is {}", MIN_AMOUNT),
            );
            return None;
        }

        // Error : invalid signature
        let public_key = sender_wallet.address.strip_prefix("SRKS_").unwrap_or("");
        if !Encryption::verify_signature(public_key, &message, signature) {
            Log::error_msg("Blockchain::Transaction", "create", "Invalid signature");
            return None;
        }

        // Check if bonus fee for referrer
        let sender_referrer_wallet =
            match Wallet::find(&pg_pool, sender_wallet.referrer.as_deref().unwrap_or("")).await {
                Ok(wallet) => wallet,
                Err(e) => {
                    Log::error(
                        "Blockchain::Transaction",
                        "create",
                        "Find sender referrer error",
                        e,
                    );
                    return None;
                }
            };

        let inactive_referrer = Wallet::is_inactive(sender_referrer_wallet.clone());
        let bonus_referrer =
            if !sender_referrer_wallet.address.is_empty() && sender_wallet.first_referrer {
                true
            } else {
                false
            };

        // Set fees
        let fee_rule = FeeRule {
            founder_percentage: if inactive_referrer {
                60_000_u64
            } else if bonus_referrer {
                30_000_u64
            } else {
                40_000_u64
            },
            treasury_percentage: 30_000_u64,
            staking_percentage: 10_000_u64,
            referral_percentage: if inactive_referrer {
                0_u64
            } else if bonus_referrer {
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
                    Log::error("Blockchain::Transaction", "create", "Get balance error", e);
                    return None;
                }
            };
            if balance < total {
                Log::error_msg(
                    "Blockchain::Transaction",
                    "create",
                    &format!("Not enough tokens, required is {}", to_srks(total)),
                );
                return None;
            }
        }

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

    /// Send a transaction
    pub async fn send(
        sender: &str,
        recipient: &str,
        amount_float: f64,
        sender_dh_public_str: &str,
        sender_dh_secret_str: &str,
        private_key: &str,
        memo_input: &str,
        pg_pool: &PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let amount: u64 = to_nanosrks(amount_float);

        // Recipient DH public/secret
        let (recipient_dh_public_str, recipient_dh_public_opt) =
            Encryption::get_dh_public_key_data_by_address(pg_pool, recipient).await?;

        let recipient_dh_public = match recipient_dh_public_opt {
            Some(key) => key,
            None => {
                Log::error_msg(
                    "blockchain::Transaction",
                    "send",
                    "Recipient DH key not found",
                );
                return Ok(());
            }
        };

        let sender_dh_secret = match Encryption::hex_to_static_secret(sender_dh_secret_str) {
            Some(secret) => secret,
            None => {
                Log::error_msg(
                    "blockchain::Transaction",
                    "send",
                    "Invalid sender DH secret",
                );
                return Ok(());
            }
        };

        // Memo
        let memo_input_truncated = &memo_input[..memo_input.len().min(255)];
        let (encrypted_memo, nonce) = Encryption::encrypt_message(
            &sender_dh_secret,
            &recipient_dh_public,
            memo_input_truncated,
        );

        let nonce_encoded = base64::engine::general_purpose::STANDARD.encode(nonce);
        let memo = if encrypted_memo.is_empty() {
            "".to_string()
        } else {
            format!("{}:{}", encrypted_memo, nonce_encoded)
        };

        // Signature
        let message = format!("{}{}{}{}{}", sender, recipient, amount, memo, Utc::now());
        let signature = Encryption::sign_message(private_key.to_string(), message.clone());

        // Transaction
        if let Some(tx) = Transaction::create(
            sender,
            recipient,
            amount,
            sender_dh_public_str,
            &recipient_dh_public_str,
            &memo,
            &signature,
            &message,
            pg_pool,
        )
        .await
        {
            // Finalize
            let (last_index, last_hash) = Block::get_last_block_meta(pg_pool).await?;
            let block = Block::new(last_index + 1, vec![tx.clone()], last_hash);

            let mut query = pg_pool.begin().await?;

            let result = {
                Block::save_to_db(&block, &mut query).await?;
                Transaction::save_to_db(&tx, block.index, &mut query).await?;
                Ledger::apply_transaction(&tx, &mut query).await?;

                Ok::<(), Box<dyn std::error::Error>>(())
            };

            // Insert
            match result {
                Ok(_) => {
                    query.commit().await?;
                    Log::info_msg(
                        "Blockchain::Transaction",
                        "send",
                        "Transaction successfully completed",
                    );
                }
                Err(e) => {
                    query.rollback().await.ok();
                    Log::error_msg("Blockchain::Transaction", "send", &format!("Error: {}", e));
                    return Err(e);
                }
            }
        }

        Ok(())
    }

    /// Saves the transaction(s) in the database if the entire transaction was successful
    pub async fn save_to_db(
        tx: &Transaction,
        block_index: u64,
        query_sync: &mut QuerySync<'_, Postgres>,
    ) -> Result<(), sqlx::Error> {
        Utils::with_timeout(
            sqlx::query!(
                "INSERT INTO core.transactions (
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
            .execute(&mut **query_sync),
            90,
        )
        .await?;

        Ok(())
    }

    /// Distribution of transaction fees
    pub fn fee_distributions(
        fee: u64,
        fee_rule: FeeRule,
        referrer_wallet: String,
    ) -> Result<Vec<(String, u64)>, std::io::Error> {
        // Stop if no fee
        if fee == 0 {
            return Ok(vec![]);
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
        let public_sale_address = Utils::read_from_file("owners/PUBLIC_SALE").map_err(|e| {
            Log::error(
                "Blockchain::Blocks",
                "fee_distributions",
                "PUBLIC_SALE",
                &e.to_string(),
            );
            e
        })?;

        let founder_address = Utils::read_from_file("owners/FOUNDER").map_err(|e| {
            Log::error(
                "Blockchain::Blocks",
                "fee_distributions",
                "FOUNDER",
                &e.to_string(),
            );
            e
        })?;

        let staking_address = Utils::read_from_file("owners/STAKING").map_err(|e| {
            Log::error(
                "Blockchain::Blocks",
                "fee_distributions",
                "STAKING",
                &e.to_string(),
            );
            e
        })?;

        let mut result = vec![
            (founder_address.clone(), shares[FOUNDER_INDEX]),
            (public_sale_address, shares[TREASURY_INDEX]),
            (staking_address, shares[STAKING_INDEX]),
        ];

        // Check referrer
        if !referrer_wallet.is_empty() {
            result.push((referrer_wallet, shares[REFERRAL_INDEX]));
        } else {
            result.push((founder_address, shares[REFERRAL_INDEX]));
        }

        Ok(result)
    }

    /// Get totals for incoming and outgoing for a wallet
    pub async fn get_totals_inout(
        pool: &PgPool,
        address: &str,
    ) -> Result<((f64, u64), (f64, u64)), sqlx::Error> {
        let incoming_fut = Utils::with_timeout(
            sqlx::query!(
                r#"
                SELECT SUM(amount)::BIGINT as sum, COUNT(*)::BIGINT as count
                FROM core.transactions
                WHERE recipient = $1
                "#,
                address
            )
            .fetch_one(pool),
            30,
        );

        let outgoing_fut = Utils::with_timeout(
            sqlx::query!(
                r#"
                SELECT SUM(amount)::BIGINT as sum, COUNT(*)::BIGINT as count
                FROM core.transactions
                WHERE sender = $1
                "#,
                address
            )
            .fetch_one(pool),
            30,
        );

        let (incoming, outgoing) = tokio::join!(incoming_fut, outgoing_fut);

        let incoming_row = incoming?;
        let outgoing_row = outgoing?;

        Ok((
            (
                to_srks(incoming_row.sum.unwrap_or(0) as u64),
                incoming_row.count.unwrap_or(0) as u64,
            ),
            (
                to_srks(outgoing_row.sum.unwrap_or(0) as u64),
                outgoing_row.count.unwrap_or(0) as u64,
            ),
        ))
    }

    /// Get rewards staking for a wallet
    pub async fn get_staking_rewards(pool: &PgPool, address: &str) -> Result<f64, sqlx::Error> {
        let staking_address = Utils::read_from_file("owners/STAKING").map_err(|e| e)?;
        let rewards = Utils::with_timeout(
            sqlx::query_scalar!(
                r#"
                SELECT SUM(amount)::BIGINT
                FROM core.transactions
                WHERE recipient = $1 AND sender = $2
                "#,
                address,
                staking_address
            )
            .fetch_one(pool),
            30,
        )
        .await?;

        Ok(to_srks(rewards.unwrap_or(0) as u64))
    }

    /// Get rewards of transaction fee of referral
    pub async fn get_fee_rewards(pool: &PgPool, address: &str) -> Result<f64, sqlx::Error> {
        let rewards = Utils::with_timeout(
            sqlx::query_scalar!(
                r#"
                SELECT SUM(fee * (fee_referral / 100000.0))::BIGINT AS referral_rewards
                FROM core.transactions
                WHERE referrer = $1
                "#,
                address.trim()
            )
            .fetch_one(pool),
            30,
        )
        .await?;

        Ok(to_srks(rewards.unwrap_or(0) as u64))
    }

    /// Get all fee of transaction
    pub async fn get_fee_transaction(pool: &PgPool, address: &str) -> Result<f64, sqlx::Error> {
        let rewards = Utils::with_timeout(
            sqlx::query_scalar!(
                r#"
                SELECT SUM(fee)::BIGINT
                FROM core.transactions
                WHERE sender = $1
                "#,
                address.trim()
            )
            .fetch_one(pool),
            30,
        )
        .await?;

        Ok(to_srks(rewards.unwrap_or(0) as u64))
    }

    /// Get incoming/outgoing transactions
    pub async fn get_all_transactions(
        pool: &PgPool,
        address: &str,
        start: u64,
    ) -> Result<Vec<GetTransaction>, sqlx::Error> {
        let transactions = sqlx::query_as!(
            GetTransaction,
            r#"
            SELECT
                sender,
                recipient,
                CASE
                    WHEN recipient = $1 THEN amount::FLOAT8 / $3
                    ELSE (amount::FLOAT8 / $3) + (fee::FLOAT8 / $3)
                END AS amount_srks,
                timestamp,
                sender_dh_public,
                recipient_dh_public,
                memo
            FROM core.transactions
            WHERE recipient = $1 OR sender = $1
            ORDER BY timestamp DESC
            OFFSET $2
            LIMIT 10
            "#,
            address,
            start as i64,
            NANOSRKS_PER_SRKS as f64
        )
        .fetch_all(pool)
        .await?;

        Ok(transactions)
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
                    Log::error_msg("Blockchain::Transaction", "decrypt_memo", "Decrypt failed");
                    "".to_string()
                }
            } else {
                Log::error_msg(
                    "Blockchain::Transaction",
                    "decrypt_memo",
                    "Convert key failed",
                );
                "".to_string()
            }
        } else {
            Log::error_msg(
                "Blockchain::Transaction",
                "decrypt_memo",
                "Separator not found",
            );
            "".to_string()
        }
    }

    /// Give free tokens for test
    pub async fn givetokens(
        pool: &PgPool,
        address: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let already_received: Option<String> = Utils::with_timeout(
            sqlx::query_scalar!(
                r#"
                    SELECT address FROM core.givetokens WHERE address = $1
                "#,
                address
            )
            .fetch_optional(pool),
            30,
        )
        .await?;

        if already_received.is_some() {
            return Err("This address has already received test tokens".into());
        }

        let public_sale_secret = VaultService::get_owner_secret(&"PUBLIC_SALE".to_string()).await?;

        let transaction = Transaction::send(
            &Wallet::add_prefix(&public_sale_secret.public_key),
            address,
            200f64,
            &public_sale_secret.dh_public,
            &public_sale_secret.dh_secret,
            &&public_sale_secret.private_key,
            &"Airdrop test".to_string(),
            &pool,
        )
        .await;

        match transaction {
            Ok(_) => {
                Log::info_msg(
                    "Blockchain::Transaction",
                    "givetokens",
                    "Givetokens successful",
                );
            }
            Err(_e) => Log::error_msg(
                "Blockchain::Transaction",
                "givetokens",
                "Transaction failed",
            ),
        }

        Utils::with_timeout(
            sqlx::query!(
                r#"
            INSERT INTO core.givetokens (address) VALUES ($1)
            "#,
                address
            )
            .execute(pool),
            30,
        )
        .await?;

        Ok(())
    }
}

/// Checking that the blockchain does not already exist
pub async fn is_empty(pool: &PgPool) -> Result<bool, sqlx::Error> {
    let mut query_sync = pool.begin().await?;

    // Check if block exists
    let count_opt = Utils::with_timeout(
        sqlx::query_scalar!("SELECT COUNT(*) FROM core.blocks").fetch_one(&mut *query_sync),
        90,
    )
    .await;

    let count = match count_opt {
        Ok(v) => v.unwrap_or(0),
        Err(e) => {
            query_sync.rollback().await.ok();
            return Err(e);
        }
    };

    // Check genesis status
    let genesis_done_res = Utils::with_timeout(
        sqlx::query_scalar!("SELECT genesis_done FROM core.system_status WHERE id = 1")
            .fetch_one(&mut *query_sync),
        90,
    )
    .await;

    let genesis_done = match genesis_done_res {
        Ok(v) => v,
        Err(e) => {
            query_sync.rollback().await.ok();
            return Err(e);
        }
    };

    // Lock to avoid concurrent init
    let lock_res = Utils::with_timeout(
        sqlx::query!("LOCK TABLE core.blocks IN ACCESS EXCLUSIVE MODE").execute(&mut *query_sync),
        90,
    )
    .await;

    if let Err(e) = lock_res {
        query_sync.rollback().await.ok();
        return Err(e);
    }

    query_sync.commit().await?;
    Ok(count == 0 && !genesis_done)
}

/// Load all blocks in json from the database
pub async fn load_blocks_from_db(pg_pool: &PgPool) -> Result<Vec<Block>, sqlx::Error> {
    let rows = Utils::with_timeout(
        sqlx::query!("SELECT raw_json FROM core.blocks ORDER BY index ASC").fetch_all(pg_pool),
        30,
    )
    .await?;

    let mut blocks = Vec::new();
    for row in rows {
        let block: Block = serde_json::from_value(row.raw_json).map_err(|e| {
            Log::error(
                "Blockchain::Blocks",
                "load_blocks_from_db",
                "Deserialize block failed",
                e.to_string(),
            );
            sqlx::Error::Protocol(e.to_string().into())
        })?;
        blocks.push(block);
    }

    Ok(blocks)
}

/// Check and fix ledger with blockchain reading
pub async fn verify_ledger(pg_pool: &PgPool) -> Result<(), DynError> {
    // Open log
    let mut log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("ledger.log")?;

    let timestamp = Utc::now().to_rfc3339();
    writeln!(log_file, "")?;
    writeln!(log_file, "[{}] Start verify ledger", timestamp)?;

    // Get wallets
    let public_sale_address = Utils::read_from_file("owners/PUBLIC_SALE").map_err(|e| {
        Log::error(
            "Blockchain",
            "verify_and_resync_ledger",
            "PUBLIC_SALE",
            &e.to_string(),
        );
        e
    })?;

    let founder_address = Utils::read_from_file("owners/FOUNDER").map_err(|e| {
        Log::error(
            "Blockchain",
            "verify_and_resync_ledger",
            "FOUNDER",
            &e.to_string(),
        );
        e
    })?;

    let staking_address = Utils::read_from_file("owners/STAKING").map_err(|e| {
        Log::error(
            "Blockchain",
            "verify_and_resync_ledger",
            "STAKING",
            &e.to_string(),
        );
        e
    })?;

    // Create a ledger temp table
    Utils::with_timeout(
        sqlx::query!(
            r#"
            CREATE TABLE IF NOT EXISTS snapshot.tmp_ledger_sync (
                address TEXT PRIMARY KEY,
                balance BIGINT NOT NULL DEFAULT 0
            )
            "#,
        )
        .execute(pg_pool),
        120,
    )
    .await?;

    // Clean table
    Utils::with_timeout(
        sqlx::query(
            r#"
             TRUNCATE snapshot.tmp_ledger_sync
            "#,
        )
        .execute(pg_pool),
        120,
    )
    .await?;

    // Streamed blocks
    let mut block_stream = sqlx::query!(
        r#"
        SELECT index
        FROM core.blocks
        ORDER BY index ASC
        "#
    )
    .fetch(pg_pool);

    while let Some(row) = Utils::with_timeout_next(&mut block_stream, 120).await? {
        let block = row?;
        let tx_stream = sqlx::query!(
            r#"
            SELECT referrer, sender, recipient, amount, fee,
            fee_founder, fee_staking, fee_referral, fee_treasury
            FROM core.transactions
            WHERE block_index = $1
            "#,
            block.index
        )
        .fetch(pg_pool);

        tokio::pin!(tx_stream);

        while let Some(tx_row) = Utils::with_timeout_next(&mut tx_stream, 120).await? {
            // Params
            let tx = tx_row?;
            let referrer = tx.referrer.unwrap_or("".to_string());
            let amount = tx.amount.max(0) as i64;
            let fee = tx.fee as i64;

            // Distribution fees
            let percentages = [
                tx.fee_founder as u64,
                tx.fee_treasury as u64,
                tx.fee_staking as u64,
                tx.fee_referral as u64,
            ];

            let shares = Transaction::split_fee_exact(fee as u64, &percentages);

            let mut result = vec![
                (&founder_address, shares[FOUNDER_INDEX]),
                (&public_sale_address, shares[TREASURY_INDEX]),
                (&staking_address, shares[STAKING_INDEX]),
            ];

            if !referrer.is_empty() {
                result.push((&referrer, shares[REFERRAL_INDEX]));
            } else {
                result.push((&founder_address, shares[REFERRAL_INDEX]));
            }

            for (address, fee_amount) in result {
                if !address.is_empty() && fee_amount > 0 {
                    Utils::with_timeout(
                        sqlx::query(
                            r#"
                            INSERT INTO snapshot.tmp_ledger_sync (address, balance)
                            VALUES ($1, $2)
                            ON CONFLICT (address)
                            DO UPDATE SET balance = snapshot.tmp_ledger_sync.balance + $2
                            "#,
                        )
                        .bind(address)
                        .bind(fee_amount as i64)
                        .execute(pg_pool),
                        120,
                    )
                    .await?;
                }
            }

            // Deduce from sender (except SRKS_GENESIS)
            if !tx.sender.is_empty() && tx.sender != "SRKS_GENESIS" {
                Utils::with_timeout(
                    sqlx::query(
                        r#"
                        INSERT INTO snapshot.tmp_ledger_sync(address, balance)
                        VALUES ($1, -$2)
                        ON CONFLICT (address)
                        DO UPDATE SET balance = snapshot.tmp_ledger_sync.balance - $2
                        "#,
                    )
                    .bind(&tx.sender)
                    .bind(amount + fee)
                    .execute(pg_pool),
                    120,
                )
                .await?;
            }

            // Add to recipient
            Utils::with_timeout(
                sqlx::query(
                    r#"
                    INSERT INTO snapshot.tmp_ledger_sync (address, balance)
                    VALUES ($1, $2)
                    ON CONFLICT (address)
                    DO UPDATE SET balance = snapshot.tmp_ledger_sync.balance + $2
                    "#,
                )
                .bind(&tx.recipient)
                .bind(amount)
                .execute(pg_pool),
                120,
            )
            .await?;
        }
        drop(tx_stream);
    }
    drop(block_stream);

    // Checking balances
    let mut real_ledger = sqlx::query(
        r#"
        SELECT wl.address, wl.balance, COALESCE(tmp.balance, 0) AS expected
        FROM core.wallet_balances wl
        LEFT JOIN snapshot.tmp_ledger_sync tmp ON wl.address = tmp.address
        "#,
    )
    .fetch(pg_pool);

    while let Some(row) = Utils::with_timeout_next(&mut real_ledger, 120).await? {
        let r = row?;
        let address: String = r.get("address");
        let balance: i64 = r.get("balance");
        let expected: i64 = r.get("expected");

        if balance != expected {
            writeln!(
                log_file,
                "Desynchronization: {} → real = {}, expected = {}",
                address, balance, expected
            )?;
        }
    }
    drop(real_ledger);

    // Drop table temp
    Utils::with_timeout(
        sqlx::query("DROP TABLE IF EXISTS snapshot.tmp_ledger_sync;").execute(pg_pool),
        120,
    )
    .await?;

    // End check
    writeln!(log_file, "End verify ledger")?;
    drop(log_file);
    Ok(())
}

/// Convert SRKS units to nanosrks
pub fn to_nanosrks(srks: f64) -> u64 {
    (srks * NANOSRKS_PER_SRKS as f64).round() as u64
}

/// Convert nanosrks to SRKS units
pub fn to_srks(nanosrks: u64) -> f64 {
    nanosrks as f64 / NANOSRKS_PER_SRKS as f64
}
