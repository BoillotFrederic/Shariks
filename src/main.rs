// Molduls
mod blockchain;
mod utils;
mod wallet;

// Dependencies
use blockchain::*;
use utils::*;
use wallet::*;
use uuid::Uuid;
use std::io;

// Main
fn main() {
    println!("Initialization start");

    // Load bloackchain
    let filename = "blockchain.json";
    let mut blockchain = load_blockchain(filename);

    // Init ledger
    let mut ledger = initialize_ledger_from_blockchain(&blockchain);

    // Create wallets for test
    let wallets = vec![
        Wallet {
            address: WALLET_GENESIS.to_string(),
            referrer: None,
        },
        Wallet {
            address: WALLET_PUBLIC_SALE.to_string(),
            referrer: None,
        },
        Wallet {
            address: WALLET_FOUNDER.to_string(),
            referrer: None,
        },
        Wallet {
            address: WALLET_SPONSORSHIP.to_string(),
            referrer: None,
        },
        Wallet {
            address: WALLET_TREASURY.to_string(),
            referrer: None,
        },
        Wallet {
            address: WALLET_STAKING.to_string(),
            referrer: None,
        },
        Wallet {
            address: "SRKS_parrain_1".to_string(),
            referrer: None,
        },
        Wallet {
            address: "SRKS_filleul_1".to_string(),
            referrer: Some("SRKS_parrain_1".to_string()),
        },
        Wallet {
            address: "SRKS_filleul_2".to_string(),
            referrer: Some("SRKS_parrain_1".to_string()),
        },
    ];

    // Create first transactions
    if blockchain.is_empty() {

        // Transaction GENESIS
        let fee_rule = FeeRule {
            rate: 0.0,
            max_fee: 0.0,
            founder_percentage: 0.0,
            treasury_percentage: 0.0,
            staking_percentage: 0.0,
            referral_percentage: 0.0,
            referral_bonus: false,
        };

        let genesis_tx = Transaction {
            id: Uuid::new_v4(),
            sender: WALLET_GENESIS.to_string(),
            recipient: WALLET_PUBLIC_SALE.to_string(),
            amount: 100000000.0,
            fee: 0.0,
            fee_rule,
            timestamp: current_timestamp(),
            referrer: None,
        };

        let genesis_block = Block::new(0, vec![genesis_tx], "0".to_string());
        blockchain.push(genesis_block.clone());
        update_ledger_with_block(&mut ledger, &genesis_block);

        // Transaction of distribution initial
        distribute_initial_tokens(&mut ledger, &wallets, &mut blockchain);

        // First block chain save
        save_blockchain(&blockchain, filename);
    }

    // Transaction ask
    loop {
        println!("\n--- Menu ---");
        println!("1. Add transaction");
        println!("2. View blocks");
        println!("3. View balances");
        println!("4. Save and quit");

        let mut choice = String::new();
        io::stdin().read_line(&mut choice).expect("Error : read line");
        match choice.trim() {
            "1" => {
                let sender = prompt("Sender :");
                let recipient = prompt("Recipient :");
                let amount: f64 = prompt("Amount :").trim().parse().unwrap_or(0.0);

                if let Some(tx) = create_transaction(&wallets, &ledger, &sender, &recipient, amount, &EXEMPT_FEES_ADDRESSES) {
                    let block = Block::new(blockchain.len() as u64, vec![tx], get_latest_hash(&blockchain));
                    update_ledger_with_block(&mut ledger, &block);
                    blockchain.push(block.clone());
                    println!("\nTransaction : {:?}", block);
                }
            }
            "2" => {
                for block in &blockchain {
                    println!("\n Block n°{} :", block.index);
                    println!("{:#?}", block);
                }
            }
            "3" => {
                view_balances(&ledger);
            }
            "4" => {
                save_blockchain(&blockchain, filename);
                println!("Bye !");
                break;
            }
            _ => println!("Error : invalid choise"),
        }
    }
}
