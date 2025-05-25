//! # Ledger Module - Shariks Chain
//!
//! The `ledger` module is responsible for managing wallet balances,
//! verifying transaction eligibility, and applying balance updates
//! as the chain evolves.

// Dependencies
use sqlx::{Error, PgPool, Postgres, Transaction as QuerySync};

// Crates
use crate::Utils;
use crate::blockchain;
use crate::blockchain::*;

// Ledger
// ------

pub struct Ledger;

impl Ledger {
    /// Apply the transaction by updating the ledger in the database but only if the entire
    /// transaction was successful
    pub async fn apply_transaction(
        tx: &Transaction,
        query_sync: &mut QuerySync<'_, Postgres>,
    ) -> Result<(), sqlx::Error> {
        let total = tx.amount + tx.fee;
        let genesis = format!("{}{}", blockchain::PREFIX_ADDRESS, "genesis");

        // Sender amount
        if tx.sender != genesis {
            let sender_balance: i64 = sqlx::query_scalar!(
                "SELECT balance FROM core.wallet_balances WHERE address = $1",
                tx.sender
            )
            .fetch_one(&mut **query_sync)
            .await?;

            if sender_balance < total as i64 {
                return Err(sqlx::Error::RowNotFound);
            }

            sqlx::query!(
                "UPDATE core.wallet_balances SET balance = balance - $1 WHERE address = $2",
                total as i64,
                tx.sender
            )
            .execute(&mut **query_sync)
            .await?;
        }

        // Payment
        sqlx::query!(
            "INSERT INTO core.wallet_balances (address, balance)
         VALUES ($1, $2)
         ON CONFLICT (address) DO UPDATE SET balance = wallet_balances.balance + $2",
            tx.recipient,
            tx.amount as i64
        )
        .execute(&mut **query_sync)
        .await?;

        // Fee distributions
        for (addr, amount) in blockchain::Transaction::fee_distributions(
            tx.fee,
            tx.fee_rule.clone(),
            tx.referrer.clone(),
        ) {
            sqlx::query!(
                "INSERT INTO core.wallet_balances (address, balance)
             VALUES ($1, $2)
             ON CONFLICT (address) DO UPDATE SET balance = core.wallet_balances.balance + $2",
                addr,
                amount as i64
            )
            .execute(&mut **query_sync)
            .await?;
        }

        Ok(())
    }

    /// Checks if the distributed tokens match the total number of tokens
    pub async fn check_total_supply(
        pool: &PgPool,
        expected_total: u64,
    ) -> Result<bool, sqlx::Error> {
        let row = sqlx::query!("SELECT SUM(balance)::BIGINT AS total FROM core.wallet_balances")
            .fetch_one(pool)
            .await?;

        let total_u64 = row.total.unwrap_or(0).max(0) as u64;

        if total_u64 == expected_total {
            println!("Total supply is correct : {} SRKS", to_srks(total_u64));
            Ok(true)
        } else {
            println!("Error : total supply incorrect");
            println!("Current : {} SRKS", to_srks(total_u64));
            println!("Expected : {} SRKS", to_srks(expected_total));
            Ok(false)
        }
    }

    /// Find the number of tokens held by a wallet
    pub async fn get_balance(pool: &PgPool, address: &str) -> Result<u64, Error> {
        let balance = sqlx::query_scalar!(
            "SELECT balance FROM core.wallet_balances WHERE address = $1",
            address
        )
        .fetch_optional(pool)
        .await?
        .unwrap_or(0);

        Ok(balance as u64)
    }

    /// List all wallets and their tokens
    pub async fn view_balances(pool: &PgPool) -> Result<(), sqlx::Error> {
        println!("\n--- Wallet balances ---");

        let rows =
            sqlx::query!("SELECT address, balance FROM core.wallet_balances ORDER BY balance DESC")
                .fetch_all(pool)
                .await?;

        for row in rows {
            println!(
                "{} : {} SRKS",
                row.address,
                Utils::trim_trailing_zeros(blockchain::to_srks(row.balance as u64))
            );
        }

        Ok(())
    }
}
