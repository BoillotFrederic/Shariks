//
//  $$$$$$\  $$\                           $$\ $$\
// $$  __$$\ $$ |                          \__|$$ |
// $$ /  \__|$$$$$$$\   $$$$$$\   $$$$$$\  $$\ $$ |  $$\  $$$$$$$\
// \$$$$$$\  $$  __$$\  \____$$\ $$  __$$\ $$ |$$ | $$  |$$  _____|
//  \____$$\ $$ |  $$ | $$$$$$$ |$$ |  \__|$$ |$$$$$$  / \$$$$$$\
// $$\   $$ |$$ |  $$ |$$  __$$ |$$ |      $$ |$$  _$$<   \____$$\
// \$$$$$$  |$$ |  $$ |\$$$$$$$ |$$ |      $$ |$$ | \$$\ $$$$$$$  |
//  \______/ \__|  \__| \_______|\__|      \__|\__|  \__|\_______/
//
// The crypto you share… that shares back
// Copyright © : 2025

// Dependencies
use shariks_core::blockchain;
use shariks_core::encryption::*;
use shariks_core::genesis::*;
use shariks_core::ledger::*;
use shariks_core::log::*;
use shariks_core::staking::*;
use shariks_core::utils::*;
use shariks_core::vault::*;
use shariks_core::wallet::*;
use sqlx::PgPool;
use std::io;

// Main
// ----

#[tokio::main]
async fn main() -> Result<(), sqlx::Error> {
    // Init log
    env_logger::init();

    // Start
    Log::info_msg("Main", "main", "Initialization start");

    // Read dotenv
    if let Err(e) = dotenvy::dotenv() {
        Log::warn("Main", "main", "Failed to load .env file", e);
    }

    // Connect to database
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|e| {
        Log::warn("Main", "main", "DATABASE_URL not found, using fallback", e);
        "".to_string()
    });
    let pg_pool = PgPool::connect(&database_url).await?;

    // Create first transactions
    if blockchain::is_empty(&pg_pool).await? {
        match Genesis::start(&pg_pool).await {
            Ok(()) => {}
            Err(e) => Log::error("Main", "main", "Genesis failed", e),
        };
    }

    // CLI ask
    loop {
        println!("\n--- Menu ---");
        println!("1. Add transaction");
        println!("2. Create a new wallet");
        println!("3. View blocks");
        println!("4. View balances");
        println!("5. Check total supply");
        println!("6. View keypair with mnemonic");
        println!("7. Wallets list");
        println!("8. Make a snapshot day");
        println!("9. Clear the staking month snapshots");
        println!("10. Fake insert for token distribution test (coming soon)");
        println!("11. Distribute staking wallet for the last month");
        println!("12. Check ledger with blockchain reading");
        println!("13. Read secret vault");
        println!("14. Quit");

        let mut choice = String::new();

        if let Err(e) = io::stdin().read_line(&mut choice) {
            Log::error("Main", "main", "Failed to read from stdin", e.to_string());
            return Err(e.into());
        }

        match choice.trim() {
            // CLI - add transaction
            "1" => {
                Log::info_msg("Main", "main", "Create a new transaction");
                let sender = Utils::prompt("Sender :");
                let recipient = Utils::prompt("Recipient :");
                let amount: f64 = Utils::prompt("Amount :").trim().parse().unwrap_or(0.0);
                let sender_dh_public_str = Utils::prompt("Public DH :");
                let sender_dh_secret_str = Utils::prompt_secret("Secret DH :");
                let private_key = Utils::prompt_secret("Private key :");
                let memo_input = Utils::prompt("Memo :");

                match blockchain::Transaction::send(
                    &sender,
                    &recipient,
                    amount,
                    &sender_dh_public_str,
                    &sender_dh_secret_str,
                    &private_key,
                    &memo_input,
                    &pg_pool,
                )
                .await
                {
                    Ok(()) => {}
                    Err(e) => {
                        Log::error("Main", "main", "Add transaction", e);
                    }
                };
            }
            // CLI - create a new wallet
            "2" => {
                Log::info_msg("Main", "main", "Create a new wallet");
                let referrer = Utils::prompt("Godfather :");
                let passphrase = Utils::prompt_secret("Passphrase :");
                let found = Wallet::exists(&pg_pool, &referrer).await.unwrap_or(false);

                if found || referrer.is_empty() {
                    match Wallet::new(
                        found,
                        "",
                        &referrer.trim(),
                        &passphrase,
                        false,
                        true,
                        &pg_pool,
                    )
                    .await
                    {
                        Ok((phrase, _public_key, _private_key, _dh_public, _dh_secret)) => {
                            println!("Mnemonic : {}", phrase)
                        }
                        Err(e) => {
                            Log::error("Main", "main", "Failed to create wallet", &e.to_string());
                            continue;
                        }
                    };
                } else {
                    Log::error_msg("Main", "main", "Referrer wallet not found");
                    continue;
                }
            }
            // CLI - print all blocks
            "3" => {
                Log::info_msg("Main", "main", "Print all blocks");
                let blocks = blockchain::load_blocks_from_db(&pg_pool).await?;
                for block in &blocks {
                    println!("\nBlock n°{} :", block.index);
                    println!("{:#?}", block);
                }
            }
            // CLI - view balances
            "4" => {
                Log::info_msg("Main", "main", "View balances");
                Ledger::view_balances(&pg_pool).await?;
            }
            // CLI - check total supply
            "5" => {
                Log::info_msg("Main", "main", "Check total supply");
                Ledger::check_total_supply(&pg_pool, 100_000_000 * blockchain::NANOSRKS_PER_SRKS)
                    .await?;
            }
            // CLI - view keys with mnemonic
            "6" => {
                Log::info_msg("Main", "main", "view keys with mnemonic");
                let mnemonic = Utils::prompt("Mnemonic :");
                let passphrase = Utils::prompt_secret("Passphrase :");
                match Encryption::restore_full_keypair_from_mnemonic(
                    &mnemonic,
                    &passphrase,
                    &pg_pool,
                )
                .await
                {
                    Ok((signing_key, verifying_key, dh_secret, dh_public)) => {
                        println!("Public key : {}", hex::encode(verifying_key.to_bytes()));
                        println!("Private key : {}", hex::encode(signing_key.to_bytes()));
                        println!("dh public : {}", hex::encode(dh_public.to_bytes()));
                        println!("dh secret : {}", hex::encode(dh_secret.to_bytes()));
                    }
                    Err(e) => {
                        Log::error("Main", "main", "Key restoration failed", e);
                        continue;
                    }
                }
            }
            // CLI - print all wallets
            "7" => {
                Log::info_msg("Main", "main", "Print all wallets");
                if let Err(e) = Wallet::print_all(&pg_pool).await {
                    Log::error("Main", "main", "Print wallets failed", e);
                    continue;
                }
            }
            // CLI - Make a snapshot day
            "8" => {
                Log::info_msg("Main", "main", "Make a snapshot day");

                match Staking::snapshot_day(&pg_pool).await {
                    Ok(()) => {
                        Log::info_msg("Main", "main", "Snapshot day has been created");
                    }
                    Err(e) => {
                        Log::error("Main", "main", "Male a snapshot day", e);
                    }
                };

                continue;
            }
            // CLI - Clear the staking month snapshots
            "9" => {
                Log::info_msg("Main", "main", "Purge staking scores");

                match Staking::purge_staking_scores_for_month(&pg_pool).await {
                    Ok(()) => {
                        Log::info_msg("Main", "main", "Table staking_scores emptied");
                    }
                    Err(e) => {
                        Log::error("Main", "main", "Purge staking scores", e);
                    }
                };

                continue;
            }
            // CLI - fake insert for token distribution test
            "10" => {
                Log::info_msg("Main", "main", "fake insert for token distribution test");
                continue;
            }

            // CLI - distribute staking wallet for the last month
            "11" => {
                Log::info_msg("Main", "main", "Distribute staking wallet");
                let pg_pool_clone = pg_pool.clone();
                tokio::spawn(async move {
                    if let Err(_) =
                        Staking::execute_monthly_staking_distribution(&pg_pool_clone).await
                    {
                        Log::error_msg("Main", "main", "Staking distribution failed");
                    } else {
                        Log::info_msg("Main", "main", "Staking distribution finished successfully");
                    }
                });
            }
            // CLI - check ledger with blockchain reading
            "12" => {
                Log::info_msg("Main", "main", "Check and fix Ledger");
                let pg_pool_clone = pg_pool.clone();
                tokio::spawn(async move {
                    match blockchain::verify_ledger(&pg_pool_clone).await {
                        Ok(_) => Log::info_msg("Main", "main", "Ledger check done"),
                        Err(e) => Log::error("Main", "main", "Ledger check failed", e),
                    }
                });
            }
            // CLI - read a secret wallet
            "13" => {
                Log::info_msg("Main", "main", "Read a secret wallet");
                let name = Utils::prompt("Name : ");
                match VaultService::get_owner_secret(&name).await {
                    Ok(secret) => {
                        let _ = Utils::secret_println(&secret.mnemonic);
                        let _ = Utils::secret_println(&secret.passphrase);
                        let _ = Utils::secret_println(&secret.public_key);
                        let _ = Utils::secret_println(&secret.private_key);
                        let _ = Utils::secret_println(&secret.dh_public);
                        let _ = Utils::secret_println(&secret.dh_secret);
                    }
                    Err(e) => {
                        Log::error("Main", "main", "Read secret failed", e);
                        continue;
                    }
                };
            }
            // CLI - quit
            "14" => {
                Log::info_msg("Main", "main", "Quit");
                break;
            }
            // Invalid choise
            _ => {
                Log::error_msg("Main", "main", "Invalid choise");
                continue;
            }
        }
    }

    Ok(())
}
