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
use wallet::*;

// Main
#[tokio::main]
async fn main() -> Result<(), sqlx::Error> {
    println!("Initialization start");

    // Connect to database
    dotenvy::dotenv().ok();
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL not set");
    let pg_pool = PgPool::connect(&database_url).await?;

    // Load bloackchain
    let mut blockchain = blockchain::load();

    // Init ledger
    let mut ledger = Ledger::initialize_from_blockchain(&blockchain);

    // Create first transactions
    if blockchain.is_empty() {
        Genesis::start(&mut blockchain, &mut ledger, &pg_pool)
            .await
            .unwrap();
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
        println!("8. Save and quit");

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
                let sender_dh_secret_str = Utils::prompt("Secret DH :");
                let private_key = Utils::prompt("Private key :");

                // Memo
                let recipient_dh_public_str =
                    Encryption::get_dh_public_key_hex_by_address(&pg_pool, &recipient).await?;
                let recipient_dh_public =
                    match Encryption::get_dh_public_key_by_address(&pg_pool, &recipient).await {
                        Ok(Some(dh_pubkey)) => dh_pubkey,
                        Ok(None) => {
                            eprintln!("Erreur : destinataire introuvable ou pas de dh_public.");
                            return Ok(());
                        }
                        Err(e) => {
                            eprintln!("Erreur SQL : {}", e);
                            return Err(e);
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
                    &ledger,
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
                    let block = blockchain::Block::new(
                        blockchain.len() as u64,
                        vec![tx],
                        blockchain::get_latest_hash(&blockchain),
                    );
                    Ledger::update_with_block(&mut ledger, &block);
                    blockchain.push(block.clone());
                    println!("\nTransaction : {:?}", block);
                }
            }
            "2" => {
                let referrer = Utils::prompt("Godfather :");
                let found = Wallet::exists(&pg_pool, &referrer).await.unwrap_or(false);

                if found || referrer.is_empty() {
                    Wallet::new(found, "", &referrer.to_string().trim(), &pg_pool).await;
                } else {
                    println!("Error : the sponsor {} is not a known wallet", referrer);
                }
            }
            "3" => {
                for block in &blockchain {
                    println!("\n Block n°{} :", block.index);
                    println!("{:#?}", block);
                }
            }
            "4" => {
                Ledger::view_balances(&ledger);
            }
            "5" => {
                blockchain::check_total_supply(&ledger, 100_000_000 * NANOSRKS_PER_SRKS);
            }
            "6" => {
                let mnemonic = Utils::prompt("Mnemonic :");
                match Encryption::restore_full_keypair_from_mnemonic(&mnemonic) {
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
                blockchain::save(&blockchain);
                println!("Bye !");
                break;
            }
            _ => println!("Error : invalid choise"),
        }
    }

    Ok(())
}
