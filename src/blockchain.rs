// Dependencies
use serde::{Deserialize, Serialize};
use serde_json;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter};
use uuid::Uuid;

// Crates
use crate::Utils;
use crate::encryption::*;
use crate::ledger;
use crate::wallet::*;

// Structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeRule {
    pub founder_percentage: u64,
    pub treasury_percentage: u64,
    pub staking_percentage: u64,
    pub referral_percentage: u64,
}

// Globals
const MIN_AMOUNT: u64 = 1000000;
pub const NANOSRKS_PER_SRKS: u64 = 1_000_000_000;
const PERCENT_BASE: u64 = 100_000;
const FEE_RATE: u64 = 1_000;
const FEE_MAX: u64 = 100 * NANOSRKS_PER_SRKS;
pub const PREFIX_ADDRESS: &str = "SRKS_";

// Types
pub type Blockchain = Vec<Block>;

// Blocks
// ------

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block {
    pub index: u64,
    pub timestamp: u128,
    pub transactions: Vec<Transaction>,
    pub previous_hash: String,
    pub hash: String,
}

impl Block {
    // New block
    pub fn new(index: u64, transactions: Vec<Transaction>, previous_hash: String) -> Self {
        let timestamp = Utils::current_timestamp();
        let mut block = Block {
            index,
            timestamp,
            transactions,
            previous_hash,
            hash: String::new(),
        };
        block.hash = block.calculate_hash();
        block
    }

    // HASH
    pub fn calculate_hash(&self) -> String {
        let data = format!(
            "{}{}{:?}{}",
            self.index, self.timestamp, self.transactions, self.previous_hash
        );
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }
}

// Transaction
// -----------

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Transaction {
    pub id: Uuid,
    pub sender: String,
    pub recipient: String,
    pub amount: u64,
    pub fee: u64,
    pub fee_rule: FeeRule,
    pub timestamp: u128,
    pub signature: String,
    pub referrer: String,
    pub sender_dh_public: String,
    pub recipient_dh_public: String,
    pub memo: String,
}

impl Transaction {
    // Create a transaction
    pub async fn create(
        ledger: &HashMap<String, u64>,
        sender: &str,
        recipient: &str,
        amount: u64,
        sender_dh_public: &str,
        recipient_dh_public: &str,
        memo: &str,
        signature: &str,
        pg_pool: &PgPool,
    ) -> Option<Transaction> {
        // Error : prefix
        if !Wallet::check_prefix(sender) {
            println!("Error : invalid sender address (must start with 'SRKS_')");
            return None;
        }
        if !Wallet::check_prefix(recipient) {
            println!("Error : invalid recipient address (must start with 'SRKS_')");
            return None;
        }

        // Error : sender is recipient
        if sender == recipient {
            println!("Error : The sender must not be the recipient");
            return None;
        }

        // Get wallets
        let sender_wallet = Wallet::find(&pg_pool, sender).await.unwrap();
        let recipient_wallet = Wallet::find(&pg_pool, recipient).await.unwrap();

        // Error : wallet not found
        if sender_wallet.address.is_empty() {
            println!("Error : sender ({}) not found", sender);
            return None;
        }
        if recipient_wallet.address.is_empty() {
            println!("Error : recipient ({}) not found", recipient);
            return None;
        }

        // Invalid amount
        if amount == 0 {
            println!("Error : Invalid amount: cannot be zero");
            return None;
        }
        if amount < MIN_AMOUNT {
            println!("Error : Amount too low: minimum required is {}", MIN_AMOUNT);
            return None;
        }

        // Error : invalid signature
        let public_key = sender_wallet.address.strip_prefix("SRKS_").unwrap_or("");
        let message = format!("{}:{}:{}:{}", sender, recipient, amount, memo);

        if !Encryption::verify_transaction(public_key, &message, signature) {
            println!("Error : invalid signature");
            return None;
        }

        // Check if bonus fee for referrer
        let sender_referrer_wallet =
            Wallet::find(&pg_pool, sender_wallet.referrer.as_deref().unwrap_or(""))
                .await
                .unwrap();

        let bonus_referrer =
            if !sender_referrer_wallet.address.is_empty() && sender_wallet.first_referrer {
                true
            } else {
                false
            };

        // Set fees
        let fee_rule = FeeRule {
            founder_percentage: if bonus_referrer {
                30_000_u64
            } else {
                40_000_u64
            },
            treasury_percentage: 30_000_u64,
            staking_percentage: 10_000_u64,
            referral_percentage: if bonus_referrer {
                30_000_u64
            } else {
                20_000_u64
            },
        };

        // Calculate fees
        let fee = if Wallet::is_exempt_fee(&pg_pool, &sender)
            .await
            .unwrap_or(false)
        {
            0
        } else {
            (amount * FEE_RATE / PERCENT_BASE).min(FEE_MAX)
        };

        let total = amount + fee;

        // Sold out
        if sender != format!("{}{}", PREFIX_ADDRESS, "genesis") {
            let balance = ledger.get(sender).unwrap_or(&0);
            if *balance < total {
                println!(
                    "Error : not enough tokens. current number of tokens {} : {}, required : {}",
                    sender,
                    super::to_srks(*balance),
                    super::to_srks(total)
                );
                return None;
            }
        }

        println!("The transaction was successfully completed");

        Some(Transaction {
            id: Uuid::new_v4(),
            sender: sender.to_string(),
            recipient: recipient.to_string(),
            amount,
            fee,
            fee_rule,
            timestamp: Utils::current_timestamp(),
            signature: signature.to_string(),
            referrer: sender_wallet.referrer.as_deref().unwrap_or("").to_string(),
            sender_dh_public: sender_dh_public.to_string(),
            recipient_dh_public: recipient_dh_public.to_string(),
            memo: memo.to_string(),
        })
    }

    // Fees distribution
    pub fn distribute_fee(
        ledger: &mut HashMap<String, u64>,
        fee: u64,
        fee_rule: FeeRule,
        referrer_wallet: String,
    ) {
        // Stop if no fee
        if fee == 0 {
            return;
        }

        // Distribution
        let percentages = [
            fee_rule.founder_percentage,
            fee_rule.treasury_percentage,
            fee_rule.staking_percentage,
            fee_rule.referral_percentage,
        ];

        let shares = Self::split_fee_exact(fee, &percentages);

        // Get wallets
        let public_sale_address =
            Utils::read_from_file(&format!("owners\\{}", "PUBLIC_SALE")).unwrap();
        let founder_address = Utils::read_from_file(&format!("owners\\{}", "FOUNDER")).unwrap();
        let staking_address = Utils::read_from_file(&format!("owners\\{}", "STAKING")).unwrap();

        // Update ledger
        *ledger.entry(founder_address.clone()).or_insert(0) += shares[0];
        *ledger.entry(public_sale_address).or_insert(0) += shares[1];
        *ledger.entry(staking_address).or_insert(0) += shares[2];

        // Check referrer
        if !referrer_wallet.is_empty() {
            *ledger.entry(referrer_wallet.to_string()).or_insert(0) += shares[3];
        } else {
            *ledger.entry(founder_address).or_insert(0) += shares[3];
        }
    }

    // Adjusting imprecision
    pub fn split_fee_exact(fee: u64, percentages: &[u64]) -> Vec<u64> {
        let mut shares: Vec<u64> = percentages.iter().map(|p| fee * p / PERCENT_BASE).collect();
        let total_allocated: u64 = shares.iter().sum();
        let remainder = fee.saturating_sub(total_allocated);

        if !shares.is_empty() {
            shares[0] += remainder;
        }

        shares
    }

    // Decrypt memo
    pub fn decrypt_memo(memo: &str, dh_secret: &str, dh_public: &str) -> String {
        if let Some((memo_b64, nonce_b64)) = memo.split_once(':') {
            if let (Some(secret), Some(pubkey), Some(nonce)) = (
                Encryption::hex_to_static_secret(dh_secret),
                Encryption::hex_to_xpubkey(dh_public),
                Encryption::b64_to_nonce(nonce_b64),
            ) {
                if let Some(plaintext) =
                    Encryption::decrypt_message(secret, &pubkey, memo_b64, nonce)
                {
                    plaintext
                } else {
                    eprintln!("Error : decrypt");
                    "".to_string()
                }
            } else {
                eprintln!("Error : convert key");
                "".to_string()
            }
        } else {
            eprintln!("Error : separator");
            "".to_string()
        }
    }
}

// Save blockchain
pub fn save(blockchain: &Vec<Block>) {
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open("blockchain.json")
        .expect("Error : unable to open output file");

    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &blockchain).expect("Error : serializing blockchain");
    println!("Blockchain saved in '{}'", "blockchain.json");
}

// Load blockchain
pub fn load() -> Vec<Block> {
    let file = File::open("blockchain.json");

    match file {
        Ok(f) => {
            let reader = BufReader::new(f);
            let blockchain: Vec<Block> = serde_json::from_reader(reader).unwrap_or_else(|_| {
                println!("Error : corrupt or empty file");
                std::process::exit(1);
            });
            println!("Blockchain loaded from '{}'", "blockchain.json");
            blockchain
        }
        Err(_) => {
            println!("Error : no existing files found, creating a new blockchain");
            vec![]
        }
    }
}

// Check integrity
pub fn check_total_supply(ledger: &ledger::LedgerMap, expected_total: u64) -> bool {
    let total: u64 = ledger.values().sum();

    if total == expected_total {
        println!("Total supply is correct : {}", to_srks(total));
        true
    } else {
        println!("Error : total supply incorrect");
        println!("Current : {} SRKS", to_srks(total));
        println!("Expected : {} SRKS", to_srks(expected_total));
        false
    }
}

// SRKS to nanosrks
pub fn to_nanosrks(srks: f64) -> u64 {
    (srks * NANOSRKS_PER_SRKS as f64).round() as u64
}

// Nanosrks to SRKS
pub fn to_srks(nanosrks: u64) -> f64 {
    nanosrks as f64 / NANOSRKS_PER_SRKS as f64
}

// Get the latest HASH
pub fn get_latest_hash(blockchain: &Vec<Block>) -> String {
    if let Some(last_block) = blockchain.last() {
        last_block.hash.clone()
    } else {
        String::from("0")
    }
}
