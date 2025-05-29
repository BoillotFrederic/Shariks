//! # Blockchain Module - Shariks Chain
//!
//! This module defines the core data structures and logic that represent
//! the Shariks blockchain itself. It maintains the chain of blocks,
//! enforces transaction validation rules, and handles block addition.

// Dependencies
//use futures::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction as QuerySync};
use uuid::Uuid;

// Crates
use crate::Utils;
use crate::encryption::*;
use crate::ledger::*;
use crate::log::*;
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
        let message = format!("{}:{}:{}:{}", sender, recipient, amount, memo);

        if !Encryption::verify_transaction(public_key, &message, signature) {
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
                    &format!("Not enough tokens, required is {}", super::to_srks(total)),
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

        Ok(result)
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
pub async fn verify_and_resync_ledger(pg_pool: &PgPool) -> Result<(), Box<dyn std::error::Error>> {
    // Create a ledger temp table
    Utils::with_timeout(
        sqlx::query(
            r#"
            CREATE TEMP TABLE tmp_ledger_sync (
                address TEXT PRIMARY KEY,
                balance BIGINT NOT NULL DEFAULT 0
            ) ON COMMIT DROP;
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
            SELECT sender, recipient, amount
            FROM core.transactions
            WHERE block_index = $1
            "#,
            block.index
        )
        .fetch(pg_pool);

        tokio::pin!(tx_stream);

        while let Some(tx_row) = Utils::with_timeout_next(&mut tx_stream, 120).await? {
            let tx = tx_row?;
            let amount = tx.amount.max(0) as i64;

            // Deduce from sender (except SRKS_GENESIS)
            if tx.sender != "SRKS_GENESIS" {
                Utils::with_timeout(
                    sqlx::query(
                        r#"
                        INSERT INTO tmp_ledger_sync (address, balance)
                        VALUES ($1, -$2)
                        ON CONFLICT (address)
                        DO UPDATE SET balance = tmp_ledger_sync.balance - $2
                        "#,
                    )
                    .bind(&tx.sender)
                    .bind(amount)
                    .execute(pg_pool),
                    120,
                )
                .await?;
            }

            // Add to recipient
            Utils::with_timeout(
                sqlx::query(
                    r#"
                    INSERT INTO tmp_ledger_sync (address, balance)
                    VALUES ($1, $2)
                    ON CONFLICT (address)
                    DO UPDATE SET balance = tmp_ledger_sync.balance + $2
                    "#,
                )
                .bind(&tx.recipient)
                .bind(amount)
                .execute(pg_pool),
                120,
            )
            .await?;
        }
    }

    // Checking balances
    let mut desync_count = 0;

    let mut real_ledger = sqlx::query(
        r#"
        SELECT wl.address, wl.balance, COALESCE(tmp.balance, 0) AS expected
        FROM core.wallet_balances wl
        LEFT JOIN tmp_ledger_sync tmp ON wl.address = tmp.address
        "#,
    )
    .fetch(pg_pool);

    while let Some(row) = Utils::with_timeout_next(&mut real_ledger, 120).await? {
        let r = row?;
        let address: String = r.get("address");
        let balance: i64 = r.get("balance");
        let expected: i64 = r.get("expected");

        if balance != expected {
            Log::error_msg(
                "Blockchain",
                "verify_and_resync_ledger",
                &format!(
                    "Desynchronization : {} → real = {}, expected = {}",
                    address, balance, expected
                ),
            );
            desync_count += 1;
        }
    }

    if desync_count == 0 {
        Log::info_msg(
            "Blockchain",
            "verify_and_resync_ledger",
            "Ledger perfectly synchronized",
        );
    } else {
        Log::error_msg(
            "Blockchain",
            "verify_and_resync_ledger",
            &format!("{} desynchronizations detected", desync_count),
        );
    }

    // Fix all desynchronizations
    if desync_count > 0 {
        Utils::with_timeout(
            sqlx::query(
                r#"
                UPDATE core.wallet_balances wl
                SET balance = tmp.balance
                FROM tmp_ledger_sync tmp
                WHERE wl.address = tmp.address AND wl.balance != tmp.balance
                "#,
            )
            .execute(pg_pool),
            120,
        )
        .await?;
    }

    // Drop table temp
    Utils::with_timeout(
        sqlx::query("DROP TABLE IF EXISTS tmp_ledger_sync;").execute(pg_pool),
        120,
    )
    .await?;

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
