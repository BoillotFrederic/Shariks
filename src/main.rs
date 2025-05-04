// Molduls
mod blockchain;
mod utils;
mod wallet;

// Dependencies
use blockchain::*;
use sqlx::PgPool;
use std::collections::HashMap;
use std::io;
use utils::*;
use uuid::Uuid;
use wallet::*;

// First set
async fn first_set(
    blockchain: &mut Vec<Block>,
    ledger: &mut HashMap<String, u64>,
    pg_pool: &PgPool,
) {
    // Public sale
    let public_sale_wallet =
        create_new_wallet(false, &"PUBLIC_SALE".to_string(), "", &pg_pool).await;

    // Transaction GENESIS
    let fee_rule = FeeRule {
        founder_percentage: 0,
        treasury_percentage: 0,
        staking_percentage: 0,
        referral_percentage: 0,
    };

    let genesis_tx = Transaction {
        id: Uuid::new_v4(),
        sender: WALLET_GENESIS.to_string(),
        recipient: public_sale_wallet.address,
        amount: 100_000_000_000_000_000,
        fee: 0,
        fee_rule,
        timestamp: current_timestamp(),
        referrer: "".to_string(),
        signature: "".to_string(),
    };

    let genesis_block = Block::new(0, vec![genesis_tx], "0".to_string());
    blockchain.push(genesis_block.clone());
    update_ledger_with_block(ledger, &genesis_block);

    // Transaction of distribution initial
    distribute_initial_tokens(ledger, blockchain, &pg_pool).await;

    // First block chain save
    save_blockchain(&blockchain);
}

// Main
#[tokio::main]
async fn main() -> Result<(), sqlx::Error> {
    println!("Initialization start");

    // Connect to database
    dotenvy::dotenv().ok();
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL not set");
    let pg_pool = PgPool::connect(&database_url).await?;

    // Load bloackchain
    let mut blockchain = load_blockchain();

    // Init ledger
    let mut ledger = initialize_ledger_from_blockchain(&blockchain);

    // Create first transactions
    if blockchain.is_empty() {
        first_set(&mut blockchain, &mut ledger, &pg_pool).await;
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
                let sender = prompt("Sender :");
                let recipient = prompt("Recipient :");
                let amount: u64 =
                    prompt("Amount :").trim().parse().unwrap_or(0) * NANOSRKS_PER_SRKS;
                let private_key = prompt("Private key :");

                let signature =
                    sign_transaction(private_key, sender.clone(), recipient.clone(), amount);

                if let Some(tx) =
                    create_transaction(&ledger, &sender, &recipient, amount, &signature, &pg_pool)
                        .await
                {
                    let block = Block::new(
                        blockchain.len() as u64,
                        vec![tx],
                        get_latest_hash(&blockchain),
                    );
                    update_ledger_with_block(&mut ledger, &block);
                    blockchain.push(block.clone());
                    println!("\nTransaction : {:?}", block);
                }
            }
            "2" => {
                let referrer = prompt("Godfather :");
                let found = wallet_exists(&pg_pool, &referrer).await.unwrap_or(false);

                if !found || referrer.is_empty() {
                    create_new_wallet(!found, "", &referrer.to_string().trim(), &pg_pool).await;
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
                view_balances(&ledger);
            }
            "5" => {
                check_total_supply(&ledger, 100_000_000 * NANOSRKS_PER_SRKS);
            }
            "6" => {
                let mnemonic = prompt("Mnemonic :");
                match restore_keypair_from_mnemonic(&mnemonic) {
                    Ok((signing_key, verifying_key)) => {
                        println!("Public key : {}", hex::encode(verifying_key.to_bytes()));
                        println!("Private key : {}", hex::encode(signing_key.to_bytes()));
                    }
                    Err(err) => eprintln!("Error : failed to restore keypair: {}", err),
                }
            }
            "7" => {
                if let Err(e) = print_all_wallets(&pg_pool).await {
                    eprintln!("Error : print wallets : {}", e);
                }
            }
            "8" => {
                save_blockchain(&blockchain);
                println!("Bye !");
                break;
            }
            _ => println!("Error : invalid choise"),
        }
    }

    Ok(())
}
