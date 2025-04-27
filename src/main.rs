// Molduls
mod blockchain;
mod utils;
mod wallet;

// Dependencies
use blockchain::*;
use std::collections::HashMap;
use std::io;
use utils::*;
use uuid::Uuid;
use wallet::*;

// First set
fn first_set(
    blockchain: &mut Vec<Block>,
    ledger: &mut HashMap<String, u64>,
    wallets: &mut Vec<Wallet>,
) {
    // Public sale
    let public_sale_wallet = create_new_wallet(false, "PUBLIC_SALE".to_string(), "");
    save_wallet_to_file(&public_sale_wallet, &public_sale_wallet.address);

    // Transaction GENESIS
    let fee_rule = FeeRule {
        rate: 0,
        max_fee: 0,
        founder_percentage: 0,
        treasury_percentage: 0,
        staking_percentage: 0,
        referral_percentage: 0,
        referral_bonus: false,
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
    };

    let genesis_block = Block::new(0, vec![genesis_tx], "0".to_string());
    blockchain.push(genesis_block.clone());
    update_ledger_with_block(ledger, &genesis_block);

    // Transaction of distribution initial
    distribute_initial_tokens(ledger, wallets, blockchain);

    // First block chain save
    save_blockchain(&blockchain);
}

// Main
fn main() {
    println!("Initialization start");

    // Load wallets
    let mut wallets = load_wallets_from_folder("wallets");

    // Load bloackchain
    let mut blockchain = load_blockchain();

    // Init ledger
    let mut ledger = initialize_ledger_from_blockchain(&blockchain);

    // Create first transactions
    if blockchain.is_empty() {
        first_set(&mut blockchain, &mut ledger, &mut wallets);
    }

    // Transaction ask
    loop {
        println!("\n--- Menu ---");
        println!("1. Add transaction");
        println!("2. Create a new wallet");
        println!("3. View blocks");
        println!("4. View balances");
        println!("5. Check total supply");
        println!("6. Save and quit");

        let mut choice = String::new();
        let addresses = EXEMPT_FEES_ADDRESSES.lock().unwrap();
        io::stdin()
            .read_line(&mut choice)
            .expect("Error : read line");
        match choice.trim() {
            "1" => {
                let sender = prompt("Sender :");
                let recipient = prompt("Recipient :");
                let amount: u64 =
                    prompt("Amount :").trim().parse().unwrap_or(0) * NANOSRKS_PER_SRKS;

                if let Some(tx) =
                    create_transaction(&wallets, &ledger, &sender, &recipient, amount, &addresses)
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
                let found = find_wallet(&wallets, &referrer).is_none();

                if !found || referrer.is_empty() {
                    let new_wallet =
                        create_new_wallet(found, "".to_string(), &referrer.to_string().trim());
                    save_wallet_to_file(&new_wallet, &new_wallet.address);
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
                save_blockchain(&blockchain);
                println!("Bye !");
                break;
            }
            _ => println!("Error : invalid choise"),
        }
    }
}
