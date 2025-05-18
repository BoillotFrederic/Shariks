//! # Still to be optimized

//! Future backend integration
//! ------------------------------------------------------
//!
//! 1. Export monthly blocks
//!```
//! use chrono::{Utc, TimeZone};
//!
//! let from = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
//! let to = Utc.with_ymd_and_hms(2025, 1, 31, 23, 59, 59).unwrap();
//!
//! Staking::export_blocks_between_dates(&pg_pool, &from, &to).await?;
//!```
//!
//! 2. Calculate holding scores
//!```
//! let scores = Staking::calculate_scores_from_stream("snapshots/blockchain_between_dates.json")?;
//!```
//!
//! 3. Calculate distribution
//!```
//! let staking_balance = 12_000 * 100_000_000;
//!
//! let distribution = Staking::generate_staking_distribution(&scores, staking_balance);
//! Staking::print_top_wallets(&distribution, 20);
//!
//!```
//! 4. Generate redistribution transactions
//!```
//! for (recipient, amount) in distribution {
//!     let tx = Transaction::create(
//!         &"SRKS_STAKING".to_string(),
//!         &recipient,
//!         amount,
//!         "", "", "",
//!         &staking_signature,
//!         &pg_pool
//!     ).await;
//! }
//!```

// Dependencies
use chrono::{DateTime, TimeZone, Utc};
use serde::ser::{SerializeSeq, Serializer};
use serde::{Deserialize, Serialize};
use serde_json::{Deserializer, ser};
use sqlx::PgPool;
use std::collections::HashMap;
use std::fs::{File, create_dir_all};
use std::io::{BufReader, BufWriter};
use std::path::Path;

// Crates
use crate::blockchain::*;

/// Defines the format of a SnapshotEntry
#[derive(Serialize)]
struct SnapshotEntry {
    address: String,
    balance: u64,
}

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
#[allow(unused)]
const STAKING_CAP: u64 = 1_000_000 * NANOSRKS_PER_SRKS;

// Staking
// -------

pub struct Staking;

#[allow(unused)]
impl Staking {
    pub fn calculate_scores_from_stream(
        path: &str,
    ) -> Result<HashMap<String, u64>, Box<dyn std::error::Error>> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let stream = Deserializer::from_reader(reader).into_iter::<ExportedBlock>();

        let mut daily_ledger: HashMap<String, u64> = HashMap::new();
        let mut scores: HashMap<String, u64> = HashMap::new();
        let mut current_day: Option<String> = None;

        for block in stream {
            let block = block?;
            let block_day = block.timestamp.format("%Y-%m-%d").to_string();

            if current_day.as_ref() != Some(&block_day) {
                for (wallet, balance) in &daily_ledger {
                    let capped = balance.min(&STAKING_CAP);
                    *scores.entry(wallet.clone()).or_default() += capped;
                }
                current_day = Some(block_day);
            }

            for tx in block.transactions {
                let sender_balance = daily_ledger.entry(tx.sender.clone()).or_insert(0);
                if *sender_balance >= tx.amount as u64 {
                    *sender_balance -= tx.amount as u64;
                }

                let recipient_balance = daily_ledger.entry(tx.recipient.clone()).or_insert(0);
                *recipient_balance += tx.amount as u64;
            }
        }

        for (wallet, balance) in &daily_ledger {
            let capped = balance.min(&STAKING_CAP);
            *scores.entry(wallet.clone()).or_default() += capped;
        }

        Ok(scores)
    }

    pub fn generate_staking_distribution(
        scores: &HashMap<String, u64>,
        staking_total: u64,
    ) -> Vec<(String, u64)> {
        let total_score: u64 = scores.values().sum();
        if total_score == 0 {
            return vec![];
        }

        let mut distribution: Vec<(String, u64)> = scores
            .iter()
            .map(|(address, score)| {
                let reward = (staking_total as u128 * *score as u128) / total_score as u128;
                (address.clone(), reward as u64)
            })
            .collect();

        // Tri du plus grand au plus petit reward
        distribution.sort_by(|a, b| b.1.cmp(&a.1));
        distribution
    }

    /// Affiche les X meilleurs wallets pour debug
    pub fn print_top_wallets(distribution: &[(String, u64)], top: usize) {
        println!("Top {} wallets:", top);
        for (i, (address, reward)) in distribution.iter().take(top).enumerate() {
            println!(
                "{:>3}. {} → {:.6} SRKS",
                i + 1,
                address,
                *reward as f64 / 100_000_000.0
            );
        }
    }

    /// Saves a snapshot of the ledger
    pub async fn save_ledger_snapshot(pg_pool: &PgPool) -> Result<(), Box<dyn std::error::Error>> {
        let folder_path = Path::new("snapshots");
        if !folder_path.exists() {
            create_dir_all(folder_path)?;
        }

        let filename = "snapshots/ledger.json";
        let file = File::create(&filename)?;
        let writer = BufWriter::new(file);
        let mut serializer = ser::Serializer::pretty(writer);
        let mut seq = serializer.serialize_seq(None)?;

        let mut rows = sqlx::query!(
            r#"
            SELECT wb.address, wb.balance
            FROM wallet_balances wb
            INNER JOIN wallets w ON w.address = wb.address
            WHERE w.staking_available = TRUE AND wb.balance > 0
            "#
        )
        .fetch(pg_pool);

        use futures::StreamExt;

        while let Some(row) = rows.next().await {
            let r = row?;
            seq.serialize_element(&SnapshotEntry {
                address: r.address,
                balance: r.balance as u64,
            })?;
        }

        seq.end()?;
        println!("Ledger snapshot write in '{}'", filename);
        Ok(())
    }

    /// Export the blockchain between two dates
    pub async fn export_blocks_between_dates(
        pg_pool: &PgPool,
        from: &DateTime<Utc>,
        to: &DateTime<Utc>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let folder_path = Path::new("snapshots");
        if !folder_path.exists() {
            create_dir_all(folder_path)?;
        }

        let from_ts = from.timestamp();
        let to_ts = to.timestamp();

        let filename = "snapshots/blockchain_between_dates.json";
        let file = File::create(filename)?;
        let writer = BufWriter::new(file);
        let mut serializer = ser::Serializer::pretty(writer);
        let mut seq = serializer.serialize_seq(None)?;

        let blocks = sqlx::query!(
            r#"
            SELECT index, timestamp
            FROM blocks
            WHERE timestamp BETWEEN $1 AND $2
            ORDER BY index ASC
            "#,
            from_ts,
            to_ts
        )
        .fetch_all(pg_pool)
        .await?;

        for block in blocks {
            let transactions = sqlx::query!(
                r#"
                SELECT sender, recipient, amount, timestamp
                FROM transactions
                WHERE block_index = $1
                ORDER BY timestamp ASC
                "#,
                block.index
            )
            .fetch_all(pg_pool)
            .await?
            .into_iter()
            .map(|tx| ExportedTransaction {
                sender: tx.sender,
                recipient: tx.recipient,
                amount: tx.amount,
                #[allow(deprecated)]
                timestamp: Utc.timestamp(tx.timestamp, 0),
            })
            .collect::<Vec<_>>();

            let block_entry = ExportedBlock {
                index: block.index,
                #[allow(deprecated)]
                timestamp: Utc.timestamp(block.timestamp, 0),
                transactions,
            };

            seq.serialize_element(&block_entry)?;
        }

        seq.end()?;

        println!("Blocks snapshot write in '{}'", filename);
        Ok(())
    }
}
