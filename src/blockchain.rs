// Dependencies
use serde::{Deserialize, Serialize};
use serde_json;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::collections::HashMap;
//use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter};
use uuid::Uuid;

// Crate
use crate::current_timestamp;
use crate::trim_trailing_zeros;
use crate::wallet::{
    add_exempt_fee_address, create_new_wallet, find_wallet, get_owner_address_wallet,
    get_owner_privatekey_wallet, is_exempt_fee_address, is_valid_address, load_wallet_owner,
    sign_transaction, verify_signature,
};

// Type
type Ledger = HashMap<String, u64>;
type Blockchain = Vec<Block>;

// Structures
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
    pub memo: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block {
    pub index: u64,
    pub timestamp: u128,
    pub transactions: Vec<Transaction>,
    pub previous_hash: String,
    pub hash: String,
}

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

// Blockchain
// ----------

impl Block {
    // New block
    pub fn new(index: u64, transactions: Vec<Transaction>, previous_hash: String) -> Self {
        let timestamp = current_timestamp();
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
    fn calculate_hash(&self) -> String {
        let data = format!(
            "{}{}{:?}{}",
            self.index, self.timestamp, self.transactions, self.previous_hash
        );
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }
}

// Create a transaction
pub async fn create_transaction(
    ledger: &HashMap<String, u64>,
    sender: &str,
    recipient: &str,
    amount: u64,
    memo: &str,
    signature: &str,
    pg_pool: &PgPool,
) -> Option<Transaction> {
    // Error : prefix
    if !is_valid_address(sender) {
        println!("Error : invalid sender address (must start with 'SRKS_')");
        return None;
    }
    if !is_valid_address(recipient) {
        println!("Error : invalid recipient address (must start with 'SRKS_')");
        return None;
    }

    // Error : sender is recipient
    if sender == recipient {
        println!("Error : The sender must not be the recipient");
        return None;
    }

    // Get wallets
    let sender_wallet = find_wallet(&pg_pool, sender).await.unwrap();
    let recipient_wallet = find_wallet(&pg_pool, recipient).await.unwrap();

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

    if !verify_signature(public_key, &message, signature) {
        println!("Error : invalid signature");
        return None;
    }

    // Check if bonus fee for referrer
    let sender_referrer_wallet =
        find_wallet(&pg_pool, sender_wallet.referrer.as_deref().unwrap_or(""))
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
    let fee = if is_exempt_fee_address(&pg_pool, &sender)
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
                sender, balance, total
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
        timestamp: current_timestamp(),
        signature: signature.to_string(),
        referrer: sender_wallet.referrer.as_deref().unwrap_or("").to_string(),
        memo: memo.to_string(),
    })
}

// Fees distribution
fn distribute_fee(
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

    let shares = split_fee_exact(fee, &percentages);

    // Get wallets
    let public_sale_wallet = load_wallet_owner(format!("first_set\\{}", "PUBLIC_SALE"));
    let founder_wallet = load_wallet_owner(format!("first_set\\{}", "FOUNDER"));
    let staking_wallet = load_wallet_owner(format!("first_set\\{}", "STAKING"));
    let public_sale_address = format!("{}{}", PREFIX_ADDRESS, public_sale_wallet.public_key);
    let founder_address = format!("{}{}", PREFIX_ADDRESS, founder_wallet.public_key);
    let staking_address = format!("{}{}", PREFIX_ADDRESS, staking_wallet.public_key);

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

// First distribution
pub async fn distribute_initial_tokens(
    ledger: &mut Ledger,
    blockchain: &mut Blockchain,
    pg_pool: &PgPool,
) {
    // Public sale
    let public_sale_address = get_owner_address_wallet("PUBLIC_SALE".to_string());
    let public_sale_private_key = get_owner_privatekey_wallet("PUBLIC_SALE".to_string());
    let public_sale_wallet = find_wallet(&pg_pool, &public_sale_address).await.unwrap();

    if let Err(e) = add_exempt_fee_address(&pg_pool, &public_sale_wallet.address).await {
        eprintln!("Error : add exempt_fees_address : {}", e);
    }

    // Wallets to be created
    let wallet_names = vec!["FOUNDER", "SPONSORSHIP", "TREASURY", "STAKING"];

    for wallet_name in wallet_names.iter() {
        let wallet = create_new_wallet(false, wallet_name, "", &pg_pool).await;
        if let Err(e) = add_exempt_fee_address(&pg_pool, &wallet.address).await {
            eprintln!("Error : add exempt_fees_address : {}", e);
        }
    }

    let distribution = vec![
        (
            get_owner_address_wallet("SPONSORSHIP".to_string()),
            10_000_000 * NANOSRKS_PER_SRKS,
        ),
        (
            get_owner_address_wallet("TREASURY".to_string()),
            10_000_000 * NANOSRKS_PER_SRKS,
        ),
    ];

    let mut transactions = Vec::new();

    for (recipient, amount) in distribution {
        // Signature
        let signature = sign_transaction(
            public_sale_private_key.to_string(),
            public_sale_address.clone(),
            recipient.clone(),
            amount,
            "Initial distribution".to_string(),
        );

        // Transaction
        if let Some(tx) = create_transaction(
            ledger,
            &public_sale_address,
            &recipient,
            amount,
            "Initial distribution",
            &signature,
            &pg_pool,
        )
        .await
        {
            apply_transaction(ledger, &tx);
            transactions.push(tx);
        }
    }

    if !transactions.is_empty() {
        let previous_block = blockchain.last().unwrap();
        let index = previous_block.index + 1;
        let timestamp = current_timestamp();
        let previous_hash = previous_block.hash.clone();

        let block = Block {
            index,
            timestamp,
            previous_hash,
            transactions: transactions.clone(),
            hash: String::new(),
        };

        let mut finalized_block = block;
        finalized_block.hash = finalized_block.calculate_hash();

        blockchain.push(finalized_block);
    }
}

// Check integrity
pub fn check_total_supply(ledger: &HashMap<String, u64>, expected_total: u64) -> bool {
    let total: u64 = ledger.values().sum();

    if total == expected_total {
        println!("Total supply is correct : {}", to_srks(total));
        true
    } else {
        println!("Error : total supply incorrect");
        println!("Total actuel : {} SRKS", to_srks(total));
        println!("Total attendu : {} SRKS", to_srks(expected_total));
        false
    }
}

// Save blockchain
pub fn save_blockchain(blockchain: &Vec<Block>) {
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
pub fn load_blockchain() -> Vec<Block> {
    let file = File::open("blockchain.json");

    match file {
        Ok(f) => {
            let reader = BufReader::new(f);
            let blockchain: Vec<Block> = serde_json::from_reader(reader).unwrap_or_else(|_| {
                println!("Error : corrupt or empty file, initializing a new string");
                vec![]
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

// ledger
// ------

// Initialize ledger
pub fn initialize_ledger_from_blockchain(blockchain: &Vec<Block>) -> HashMap<String, u64> {
    let mut ledger: HashMap<String, u64> = HashMap::new();

    for block in blockchain {
        for tx in &block.transactions {
            if tx.sender != format!("{}{}", PREFIX_ADDRESS, "genesis") {
                *ledger.entry(tx.sender.clone()).or_insert(0) -= tx.amount + tx.fee;
            }

            *ledger.entry(tx.recipient.clone()).or_insert(0) += tx.amount;

            distribute_fee(
                &mut ledger,
                tx.fee,
                tx.fee_rule.clone(),
                tx.referrer.to_string(),
            );
        }
    }

    ledger
}

// Update ledger
pub fn update_ledger_with_block(ledger: &mut HashMap<String, u64>, block: &Block) {
    for tx in &block.transactions {
        if !apply_transaction(ledger, tx) {
            println!("Warning: transaction {:?} failed to apply", tx);
        }
    }
}

// Apply transaction
fn apply_transaction(ledger: &mut Ledger, tx: &Transaction) -> bool {
    let sender_balance = ledger.get(&tx.sender).unwrap_or(&0);
    let total = tx.amount + tx.fee;
    let genesis = format!("{}{}", PREFIX_ADDRESS, "genesis");

    if *sender_balance >= total || tx.sender == genesis {
        if tx.sender != genesis {
            *ledger.entry(tx.sender.clone()).or_insert(0) -= total;
        }
        *ledger.entry(tx.recipient.clone()).or_insert(0) += tx.amount;

        distribute_fee(ledger, tx.fee, tx.fee_rule.clone(), tx.referrer.to_string());

        true
    } else {
        false
    }
}

// Helpers
// -------

pub fn to_nanosrks(srks: f64) -> u64 {
    (srks * NANOSRKS_PER_SRKS as f64).round() as u64
}

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

// View balances
pub fn view_balances(ledger: &HashMap<String, u64>) {
    println!("\n--- Wallet balances ---");
    for (adresse, solde) in ledger.iter() {
        println!(
            "{} : {} SRKS",
            adresse,
            trim_trailing_zeros(to_srks(*solde))
        );
    }
}
