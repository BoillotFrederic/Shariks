//! # Staking Module – Shariks Chain
//!
//! The `staking` module manages the monthly distribution of staking rewards
//! to eligible wallet holders, based on their average token holdings and activity.
//!
//! It operates without Proof of Work, relying instead on a hybrid Proof of Stake
//! and Proof of Relay system. This module is tightly integrated with the ledger
//! and database for efficient and verifiable reward calculation.
//!
//! - **Holder Scoring System**
//!   - Uses a time-weighted score per wallet based on:
//!     - Daily token balances (snapshot-based).
//!     - Activity status (`last_login` within 12 months).
//!     - Eligibility flag (`staking_available = TRUE`).
//!     - A hard cap at **1% of total supply** per wallet to avoid dominance.
//!
//! - **Efficient SQL-Based Calculation**
//!   - All calculations are streamed via PostgreSQL to minimize RAM usage.
//!   - Results are written to a dedicated `staking_scores` table with `completed` flags for tracking.
//!
//! - **Grouped Transaction Injection**
//!   - Reward transactions are batched (e.g. 1000 per block) for performance and scalability.
//!
//! - **Automatic Cleanup & Resync**
//!   - Old snapshots are purged monthly.
//!   - Ledger synchronization is verified before each distribution to ensure chain integrity.
//!
//! This module implements a fair and scalable reward system aligned with Shariks' vision:
//! energy-efficient, community-driven, and referral-enhanced staking.

// Dependencies
use chrono::{DateTime, Datelike, Duration, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row, Transaction as QuerySync};

// Crates
use crate::blockchain::*;
use crate::encryption::*;
use crate::ledger::*;
use crate::log::*;
use crate::utils::*;
use crate::vault::*;
use crate::wallet::*;

// Types
type DynError = Box<dyn std::error::Error>;

/// Defines the format of a Transaction for export
#[derive(Debug, Serialize, Deserialize)]
struct ExportedBlock {
    index: i64,
    timestamp: DateTime<Utc>,
    transactions: Vec<ExportedTransaction>,
}

/// Defines the format of a Transaction for export
#[derive(Debug, Serialize, Deserialize)]
struct ExportedTransaction {
    sender: String,
    recipient: String,
    amount: i64,
    timestamp: DateTime<Utc>,
}

// Globals
const STAKING_CAP: u64 = 1_000_000 * NANOSRKS_PER_SRKS;

// Staking
// -------

pub struct Staking;

impl Staking {
    /// Calulate all wallet scores
    pub async fn calculate_scores(
        pg_pool: &PgPool,
        from: NaiveDate,
        to: NaiveDate,
    ) -> Result<(), DynError> {
        // Start date
        let mut current_day = from;

        // Set scores for this current day
        while current_day <= to {
            // Load
            let date_str = format!("{:02}", current_day.day());
            let snapshot_table = format!("snapshot.wallet_balances_snapshot_day_{}", date_str);
            let sql = &format!(
                r#"
                SELECT s.address, s.balance
                FROM {} s
                INNER JOIN core.wallets w ON s.address = w.address
                WHERE s.balance > 0
                AND w.staking_available = TRUE
                AND w.last_login >= now() - INTERVAL '1 year'
                "#,
                snapshot_table
            );

            let mut stream = sqlx::query(&sql).fetch(pg_pool);

            // Set
            while let Some(row) = Utils::with_timeout_next(&mut stream, 30).await? {
                let row = row?;
                let address: String = row.get("address");
                let balance: i64 = row.get("balance");
                let score = (balance as u64).min(STAKING_CAP);

                Utils::with_timeout(
                    sqlx::query!(
                        r#"
                        INSERT INTO core.staking_scores (address, score)
                        VALUES ($1, $2)
                        ON CONFLICT (address)
                        DO UPDATE SET score = staking_scores.score + $2
                        "#,
                        address,
                        score as i64
                    )
                    .execute(pg_pool),
                    30,
                )
                .await?;
            }

            current_day += Duration::days(1);
        }

        Log::info_msg("Staking", "calculate_scores", "Calculate scores completed");
        Ok(())
    }

    /// Generate all reward distribution
    pub async fn generate_distribution(
        pg_pool: &PgPool,
        staking_wallet: &str,
        staking_private_key: &str,
    ) -> Result<(), DynError> {
        // Get total score
        let value: Option<i64> = Utils::with_timeout(
            sqlx::query_scalar!(
                r#"
                SELECT SUM(score)::BIGINT as total_score
                FROM core.staking_scores
                WHERE completed = false
                "#
            )
            .fetch_one(pg_pool),
            30,
        )
        .await?;
        let total_score = value.unwrap_or(0);

        // Exists if no score found
        if total_score == 0 {
            return Ok(());
        }

        // Accumulated staking
        let staking_balance = Ledger::get_balance(pg_pool, staking_wallet).await?;
        let mut tx_buffer: Vec<Transaction> = Vec::with_capacity(1000);
        let mut addr_buffer: Vec<String> = Vec::with_capacity(1000);

        let sql = r#"
            SELECT address, score
            FROM core.staking_scores
            WHERE completed = false AND score > 0
            "#;

        let mut stream = sqlx::query(sql).fetch(pg_pool);

        while let Some(row) = Utils::with_timeout_next(&mut stream, 30).await? {
            let row = row?;
            let address: String = row.get("address");
            let score: i64 = row.get("score");
            let reward = ((score as f64 / total_score as f64) * staking_balance as f64) as u64;

            if reward <= 0 {
                return Ok(());
            }

            let signature = Encryption::sign_transaction(
                staking_private_key.to_string(),
                staking_wallet.to_string(),
                address.clone(),
                reward,
                "".to_string(),
            );

            if let Some(tx_obj) = Transaction::create(
                staking_wallet,
                &address,
                reward,
                "",
                "",
                "",
                &signature,
                pg_pool,
            )
            .await
            {
                tx_buffer.push(tx_obj);
                addr_buffer.push(address);
            }

            // As soon as we reach 1000 transactions, flush in a block
            if tx_buffer.len() == 1000 {
                Self::flush_block(pg_pool, &tx_buffer, &addr_buffer).await?;
                tx_buffer.clear();
                addr_buffer.clear();
            }
        }

        // Process the remainder if < 1000
        if !tx_buffer.is_empty() {
            Self::flush_block(pg_pool, &tx_buffer, &addr_buffer).await?;
        }

        Log::info_msg(
            "Staking",
            "generate_distribution",
            "Staking distribution completed",
        );
        Ok(())
    }

    /// Groups multiple transactions into one block
    async fn flush_block(
        pg_pool: &PgPool,
        transactions: &[Transaction],
        addresses: &[String],
    ) -> Result<(), DynError> {
        let (last_index, last_hash) = Block::get_last_block_meta(pg_pool).await?;
        let block = Block::new(last_index + 1, transactions.to_vec(), last_hash);
        let mut tx: QuerySync<'_, sqlx::Postgres> = pg_pool.begin().await?;

        let result = {
            Block::save_to_db(&block, &mut tx).await?;

            for tx_obj in transactions {
                Transaction::save_to_db(tx_obj, block.index, &mut tx).await?;
                Ledger::apply_transaction(tx_obj, &mut tx).await?;
            }

            for address in addresses {
                Utils::with_timeout(
                    sqlx::query(
                        r#"
                        UPDATE core.staking_scores
                        SET completed = TRUE
                        WHERE address = $1
                        "#,
                    )
                    .bind(address)
                    .execute(&mut *tx),
                    90,
                )
                .await?;
            }

            Ok::<(), Box<dyn std::error::Error>>(())
        };

        match result {
            Ok(_) => {
                tx.commit().await?;
                Ok(())
            }
            Err(e) => {
                tx.rollback().await.ok();
                Err(e)
            }
        }
    }

    /// Start disritution of staking token for the last month
    pub async fn execute_monthly_staking_distribution(pg_pool: &PgPool) -> Result<(), DynError> {
        // Dafe date
        pub fn safe_date(year: i32, month: u32, day: u32) -> Result<NaiveDate, DynError> {
            NaiveDate::from_ymd_opt(year, month, day).ok_or_else(|| "Invalid date".into())
        }

        // Last month
        let now = Utc::now().naive_utc().date();
        let (year, month) = if now.month() == 1 {
            (now.year() - 1, 12)
        } else {
            (now.year(), now.month() - 1)
        };

        let from = match safe_date(year, month, 1) {
            Ok(date) => date,
            Err(e) => {
                Log::error(
                    "Staking",
                    "calculate_scores",
                    "Invalid first day of month",
                    &e.to_string(),
                );
                return Err(e);
            }
        };
        let to = match Self::last_day_of_month(year, month) {
            Some(day) => safe_date(year, month, day)?,
            None => {
                Log::error(
                    "Staking",
                    "calculate_scores",
                    "Invalid last day of month",
                    format!("year: {}, month: {}", year, month),
                );
                return Err("Invalid last day of month".into());
            }
        };

        // Calculate the scores
        Self::calculate_scores(pg_pool, from, to).await?;

        // Generate distribution
        let staking_secret = VaultService::get_owner_secret(&"STAKING".to_string()).await?;
        let staking_address = Wallet::add_prefix(&staking_secret.public_key);
        let staking_private_key = staking_secret.private_key;
        Self::generate_distribution(pg_pool, &staking_address, &staking_private_key).await?;

        // Clear
        Self::purge_staking_scores_for_month(pg_pool).await?;

        Ok(())
    }

    /// Clear the staking month tables
    pub async fn purge_staking_scores_for_month(pg_pool: &PgPool) -> Result<(), DynError> {
        // Drop snapshot day tables
        for day in 1..=31 {
            let table_name = format!("snapshot.wallet_balances_snapshot_day_{:02}", day);

            let sql = format!("DROP TABLE IF EXISTS {};", table_name);
            Utils::with_timeout(sqlx::query(&sql).execute(pg_pool), 30).await?;
        }

        // Clear the score table
        Utils::with_timeout(
            sqlx::query("DELETE FROM core.staking_scores").execute(pg_pool),
            30,
        )
        .await?;

        Log::info_msg(
            "Staking",
            "purge_staking_scores_for_month",
            "Table staking_scores emptied",
        );
        Ok(())
    }

    /// Take a snapshot of wallet balances
    #[allow(unused)]
    pub async fn snapshot_day(pg_pool: &PgPool) -> Result<(), DynError> {
        // Day to string
        let yesterday = Utc::now() - Duration::days(1);
        let day = yesterday.day();
        let day_str = format!("{:02}", day);

        // Table name
        let snapshot_table = format!("snapshot.wallet_balances_snapshot_day_{}", day_str);

        // Duplicate table
        let sql = format!(
            "CREATE TABLE IF NOT EXISTS {} AS SELECT * FROM core.wallet_balances;",
            snapshot_table
        );
        Utils::with_timeout(sqlx::query(&sql).execute(pg_pool), 90).await?;

        Log::info_msg("Staking", "snapshot_day", "Snapshot day has been created");
        Ok(())
    }

    // Delete a snapshot
    #[allow(unused)]
    pub async fn delete_snapshot(pg_pool: &PgPool, table_name: i32) -> Result<(), DynError> {
        let sql = format!("DROP TABLE IF EXISTS {};", table_name);
        Utils::with_timeout(sqlx::query(&sql).execute(pg_pool), 30).await?;

        Log::info_msg("Staking", "delete_snapshot", "Snapshot has been deleted");
        Ok(())
    }

    /// Return a number days in month
    #[allow(unused)]
    fn num_days_in_month(year: i32, month: u32) -> u32 {
        fn is_leap_year(year: i32) -> bool {
            (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
        }

        match month {
            1 => 31,
            2 => {
                if is_leap_year(year) {
                    29
                } else {
                    28
                }
            }
            3 => 31,
            4 => 30,
            5 => 31,
            6 => 30,
            7 => 31,
            8 => 31,
            9 => 30,
            10 => 31,
            11 => 30,
            12 => 31,
            _ => 30,
        }
    }

    // Return the last day of month
    fn last_day_of_month(year: i32, month: u32) -> Option<u32> {
        let next_month = if month == 12 {
            NaiveDate::from_ymd_opt(year + 1, 1, 1)
        } else {
            NaiveDate::from_ymd_opt(year, month + 1, 1)
        }?;

        let last_day = next_month - Duration::days(1);
        Some(last_day.day())
    }
}
