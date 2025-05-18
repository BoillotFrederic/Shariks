//!
//!  $$$$$$\  $$\                           $$\ $$\
//! $$  __$$\ $$ |                          \__|$$ |
//! $$ /  \__|$$$$$$$\   $$$$$$\   $$$$$$\  $$\ $$ |  $$\  $$$$$$$\
//! \$$$$$$\  $$  __$$\  \____$$\ $$  __$$\ $$ |$$ | $$  |$$  _____|
//!  \____$$\ $$ |  $$ | $$$$$$$ |$$ |  \__|$$ |$$$$$$  / \$$$$$$\
//! $$\   $$ |$$ |  $$ |$$  __$$ |$$ |      $$ |$$  _$$<   \____$$\
//! \$$$$$$  |$$ |  $$ |\$$$$$$$ |$$ |      $$ |$$ | \$$\ $$$$$$$  |
//!  \______/ \__|  \__| \_______|\__|      \__|\__|  \__|\_______/
//!
//! The crypto you share… that shares back
//! Copyright © : 2025

// Molduls
mod blockchain;
mod encryption;
mod genesis;
mod ledger;
mod utils;
mod vault;
mod wallet;

// Dependencies
use base64::Engine;
use blockchain::*;
use encryption::*;
use genesis::*;
use ledger::*;
use sqlx::PgPool;
use std::io;
use utils::*;
//use vault::*;
use wallet::*;

// Main
#[tokio::main]
async fn main() -> Result<(), sqlx::Error> {
    println!("Initialization start");

    // Connect to dotenv
    dotenvy::dotenv().ok();

    // Connect to database
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL not set");
    let pg_pool = PgPool::connect(&database_url).await?;

    // Create first transactions
    if blockchain::is_empty(&pg_pool).await? {
        match Genesis::start(&pg_pool).await {
            Ok(()) => {}
            Err(e) => println!("Error : {}", e),
        };
    }

    // Transaction ask
    loop {
        println!("\n--- Menu ---");
        println!("1. Add transaction");
        println!("2. Create a new wallet");
        println!("3. View blocks");
        println!("4. View balances");
        println!("5. Check total supply");
        println!("6. View keypair with mnemonic");
        println!("7. Wallets list");
        println!("8. Decrypt memo");
        println!("9. Quit");

        let mut choice = String::new();

        io::stdin()
            .read_line(&mut choice)
            .expect("Error : read line");
        match choice.trim() {
            "1" => {
                let sender = Utils::prompt("Sender :");
                let recipient = Utils::prompt("Recipient :");
                let amount: u64 = blockchain::to_nanosrks(
                    Utils::prompt("Amount :").trim().parse().unwrap_or(0.0),
                );
                let sender_dh_public_str = Utils::prompt("Public DH :");
                let sender_dh_secret_str = Utils::prompt_secret("Secret DH :");
                let private_key = Utils::prompt_secret("Private key :");

                // Memo
                let (recipient_dh_public_str, recipient_dh_public_opt) =
                    Encryption::get_dh_public_key_data_by_address(&pg_pool, &recipient).await?;

                let recipient_dh_public = match recipient_dh_public_opt {
                    Some(key) => key,
                    None => {
                        eprintln!("Erreur : destinataire introuvable ou pas de dh_public.");
                        return Ok(());
                    }
                };

                let sender_dh_secret = match Encryption::hex_to_static_secret(&sender_dh_secret_str)
                {
                    Some(secret) => secret,
                    None => {
                        eprintln!("Error : dh_secret invalid");
                        return Ok(());
                    }
                };
                let memo_input = Utils::prompt("Memo :");
                let memo_input_truncated = &memo_input[..memo_input.len().min(255)];
                let (encrypted_memo, nonce) = Encryption::encrypt_message(
                    &sender_dh_secret,
                    &recipient_dh_public,
                    &memo_input_truncated,
                );

                let nonce_encoded = base64::engine::general_purpose::STANDARD.encode(nonce);

                let memo = if encrypted_memo.is_empty() {
                    "".to_string()
                } else {
                    format!("{}:{}", encrypted_memo, nonce_encoded)
                };

                let signature = Encryption::sign_transaction(
                    private_key,
                    sender.clone(),
                    recipient.clone(),
                    amount,
                    memo.clone(),
                );

                if let Some(tx) = blockchain::Transaction::create(
                    &sender,
                    &recipient,
                    amount,
                    &sender_dh_public_str,
                    &recipient_dh_public_str,
                    &memo,
                    &signature,
                    &pg_pool,
                )
                .await
                {
                    let (last_index, last_hash) =
                        blockchain::Block::get_last_block_meta(&pg_pool).await?;
                    let block = blockchain::Block::new(last_index + 1, vec![tx.clone()], last_hash);

                    // Finalize transaction
                    let mut query_sync = pg_pool.begin().await?;
                    blockchain::Block::save_to_db(&block, &mut query_sync).await?;
                    blockchain::Transaction::save_to_db(&tx, block.index, &mut query_sync).await?;
                    Ledger::apply_transaction(&tx, &mut query_sync).await?;
                    query_sync.commit().await?;

                    println!("\nTransaction : {:?}", block);
                }
            }
            "2" => {
                let referrer = Utils::prompt("Godfather :");
                let passphrase = Utils::prompt_secret("Passphrase :");
                let found = Wallet::exists(&pg_pool, &referrer).await.unwrap_or(false);

                if found || referrer.is_empty() {
                    Wallet::new(
                        found,
                        "",
                        &referrer.trim(),
                        &passphrase,
                        false,
                        true,
                        &pg_pool,
                    )
                    .await;
                } else {
                    println!("Error : the sponsor {} is not a known wallet", referrer);
                }
            }
            "3" => {
                let blocks = blockchain::load_blocks_from_db(&pg_pool).await?;
                for block in &blocks {
                    println!("\nBlock n°{} :", block.index);
                    println!("{:#?}", block);
                }
            }
            "4" => {
                Ledger::view_balances(&pg_pool).await?;
            }
            "5" => {
                Ledger::check_total_supply(&pg_pool, 100_000_000 * NANOSRKS_PER_SRKS).await?;
            }
            "6" => {
                let mnemonic = Utils::prompt("Mnemonic :");
                let passphrase = Utils::prompt_secret("Passphrase :");
                match Encryption::restore_full_keypair_from_mnemonic(&mnemonic, &passphrase) {
                    Ok((signing_key, verifying_key, dh_secret, dh_public)) => {
                        println!("Public key : {}", hex::encode(verifying_key.to_bytes()));
                        println!("Private key : {}", hex::encode(signing_key.to_bytes()));
                        println!("dh public : {}", hex::encode(dh_public.to_bytes()));
                        println!("dh secret : {}", hex::encode(dh_secret.to_bytes()));
                    }
                    Err(err) => eprintln!("Error : failed to restore keypair: {}", err),
                }
            }
            "7" => {
                if let Err(e) = Wallet::print_all(&pg_pool).await {
                    eprintln!("Error : print wallets : {}", e);
                }
            }
            "8" => {
                let memo = Utils::prompt("Memo : ");
                let dh_public = Utils::prompt("DH public : ");
                let dh_secret = Utils::prompt_secret("DH secret : ");

                let memo_decrypted =
                    blockchain::Transaction::decrypt_memo(&memo, &dh_secret, &dh_public);
                println!("{}", memo_decrypted);
            }
            "9" => {
                println!("Bye !");
                break;
            }
            _ => println!("Error : invalid choise"),
        }
    }

    Ok(())
}
