//! # FakeInsert Module - Shariks Chain
//!
//! Only to simulate real conditions at the end of the test

// Dependencies
use anyhow;
use chrono::NaiveDate;
use rand::{Rng, thread_rng};
use sqlx::{PgPool, query};
use time::OffsetDateTime;

// Crates
use crate::blockchain;
use crate::vault::*;
use crate::wallet::*;

// Structs
#[derive(sqlx::FromRow)]
struct FakeWalletKeys {
    public_key: Option<String>,
    private_key: Option<String>,
    dh_public: Option<String>,
    dh_secret: Option<String>,
}

// Ledger
// ------

pub struct FakeInsert;

impl FakeInsert {
    /// Mixer all
    pub async fn mixer(
        pool: &PgPool,
        year: i32,
        month: u32,
        months_back: i64,
        count_wallet: usize,
        count_tx: usize,
    ) {
        Self::date_retreat(pool, months_back).await.unwrap();
        Self::wallets(pool, year, month, count_wallet)
            .await
            .unwrap();

        let public_sale_count = count_tx - (count_tx / 10);
        Self::transactions(pool, "PUBLIC_SALE", year, month, public_sale_count)
            .await
            .unwrap();

        let random_wallet_count = count_tx - public_sale_count;
        Self::transactions(pool, "", year, month, random_wallet_count)
            .await
            .unwrap();
    }

    /// Shift timestamp bloks and transactions by number month
    pub async fn date_retreat(pool: &PgPool, months: i64) -> anyhow::Result<()> {
        use sqlx::query;
        let offset_millis = months * 30 * 24 * 60 * 60 * 1000;

        // Shift blocks
        query!(
            "UPDATE core.blocks SET timestamp = timestamp - $1",
            offset_millis
        )
        .execute(pool)
        .await?;

        // Shift transactions
        query!(
            "UPDATE core.transactions SET timestamp = timestamp - $1",
            offset_millis
        )
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Generate of fake wallets
    pub async fn wallets(pool: &PgPool, year: i32, month: u32, count: usize) -> anyhow::Result<()> {
        // Between dates
        let start_date = NaiveDate::from_ymd_opt(year, month, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();
        let end_date = if month == 12 {
            NaiveDate::from_ymd_opt(year + 1, 1, 1)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap()
        } else {
            NaiveDate::from_ymd_opt(year, month + 1, 1)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap()
        };

        // Generating loop
        let mut rng = thread_rng();
        let start_ts = start_date.and_utc().timestamp_millis();
        let end_ts = end_date.and_utc().timestamp_millis();
        let duration = end_ts - start_ts;

        for _i in 0..count {
            // Create wallet
            let referrer = if rng.gen_bool(0.5) {
                if let Ok(public_key) = sqlx::query_scalar!(
                    "SELECT public_key FROM core.fake_wallets ORDER BY RANDOM() LIMIT 1"
                )
                .fetch_one(pool)
                .await
                {
                    Wallet::add_prefix(&public_key)
                } else {
                    "".to_string()
                }
            } else {
                "".to_string()
            };

            match Wallet::new(
                !referrer.is_empty(),
                "",
                &referrer,
                "123",
                false,
                true,
                pool,
            )
            .await
            {
                Ok((_phrase, public_key, private_key, dh_public, dh_secret)) => {
                    // Random date
                    let random_offset = rng.gen_range(0..duration);
                    let login_ts = start_ts + random_offset;
                    let login_dt = OffsetDateTime::from_unix_timestamp(login_ts / 1000)?;

                    // Save wallet data
                    query!(
                        "INSERT INTO core.fake_wallets
                        (public_key, private_key, dh_public, dh_secret)
                        VALUES ($1, $2, $3, $4)",
                        public_key,
                        private_key,
                        dh_public,
                        dh_secret
                    )
                    .execute(pool)
                    .await?;

                    // Update last_login
                    sqlx::query!(
                        "UPDATE core.wallets SET last_login = $1 WHERE address = $2",
                        login_dt,
                        Wallet::add_prefix(&public_key)
                    )
                    .execute(pool)
                    .await?;
                }
                Err(_) => {}
            };
        }

        Ok(())
    }

    /// Generate of fake transactions
    pub async fn transactions(
        pool: &PgPool,
        sender: &str,
        year: i32,
        month: u32,
        count: usize,
    ) -> anyhow::Result<()> {
        // Between dates
        let start_date = NaiveDate::from_ymd_opt(year, month, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();
        let end_date = if month == 12 {
            NaiveDate::from_ymd_opt(year + 1, 1, 1)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap()
        } else {
            NaiveDate::from_ymd_opt(year, month + 1, 1)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap()
        };
        let mut rng = thread_rng();

        // Sender wallet data
        let (sender_public_key, sender_private_key, sender_dh_public, sender_dh_secret) = if sender
            .is_empty()
        {
            let sender_data = sqlx::query_as!(
                FakeWalletKeys,
                "SELECT public_key, private_key, dh_public, dh_secret FROM core.fake_wallets ORDER BY RANDOM() LIMIT 1"
            )
            .fetch_one(pool)
            .await?;

            (
                sender_data.public_key.unwrap(),
                sender_data.private_key.unwrap(),
                sender_data.dh_public.unwrap(),
                sender_data.dh_secret.unwrap(),
            )
        } else {
            let sender_secret = VaultService::get_owner_secret(sender)
                .await
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            (
                sender_secret.public_key,
                sender_secret.private_key,
                sender_secret.dh_public,
                sender_secret.dh_secret,
            )
        };

        // Random recepient wallets
        let recipient_wallets: Vec<String> = sqlx::query_scalar!(
            "SELECT address FROM core.wallets WHERE address != $1 ORDER BY RANDOM() LIMIT $2",
            Wallet::add_prefix(&sender_public_key),
            count as i64
        )
        .fetch_all(pool)
        .await?;

        // Sender balance
        let sender_balance_row = sqlx::query!(
            "SELECT balance FROM core.wallet_balances WHERE address = $1",
            Wallet::add_prefix(&sender_public_key)
        )
        .fetch_one(pool)
        .await?;
        let sender_balance = sender_balance_row.balance;
        let sender_balance_part = Self::random_part(sender_balance, count);

        // Transactions
        let start_ts = start_date.and_utc().timestamp_millis();
        let end_ts = end_date.and_utc().timestamp_millis();
        let duration = end_ts - start_ts;

        for i in 0..count {
            let tx_timestamp = start_ts + rng.gen_range(0..duration);
            let recipient = &recipient_wallets[i % recipient_wallets.len()];
            let amount = blockchain::to_srks(sender_balance_part[i] as u64);
            let memo = if rng.gen_bool(0.5) {
                format!("Memo fake : {}", recipient)
            } else {
                String::new()
            };

            match blockchain::Transaction::send(
                &sender_public_key,
                &recipient,
                amount,
                &sender_dh_public,
                &sender_dh_secret,
                &sender_private_key,
                &memo,
                &pool,
            )
            .await
            {
                Ok(()) => {}
                Err(_) => {}
            };

            // Update timestamp transaction
            let last_tx_id_row =
                sqlx::query!("SELECT id FROM core.transactions ORDER BY timestamp DESC LIMIT 1")
                    .fetch_one(pool)
                    .await?;

            let last_tx_id = last_tx_id_row.id;

            sqlx::query!(
                "UPDATE core.transactions SET timestamp = $1 WHERE id = $2",
                tx_timestamp,
                last_tx_id
            )
            .execute(pool)
            .await?;
        }

        // Update last_login sender wallet
        let last_tx_row = sqlx::query!(
            "SELECT timestamp FROM core.transactions WHERE sender = $1 ORDER BY timestamp DESC LIMIT 1",
            Wallet::add_prefix(&sender_public_key)
        )
        .fetch_optional(pool)
        .await?;

        if let Some(row) = last_tx_row {
            let login_dt = OffsetDateTime::from_unix_timestamp(row.timestamp / 1000)?;
            sqlx::query!(
                "UPDATE core.wallets SET last_login = $1 WHERE address = $2",
                login_dt,
                Wallet::add_prefix(&sender_public_key)
            )
            .execute(pool)
            .await?;
        }

        Ok(())
    }

    /// Generate a ramdom part vec
    fn random_part(total: i64, parts: usize) -> Vec<i64> {
        assert!(parts > 0 && total >= 0);

        if parts == 1 {
            return vec![total];
        }

        let mut rng = rand::thread_rng();
        let mut cuts: Vec<i64> = (0..(parts - 1)).map(|_| rng.gen_range(1..total)).collect();

        cuts.sort_unstable();
        cuts.insert(0, 0);
        cuts.push(total);
        cuts.windows(2).map(|w| w[1] - w[0]).collect()
    }
}
