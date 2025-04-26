// Dependencies
use serde::{Deserialize, Serialize};
use serde_json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter /*, Write*/};
use uuid::Uuid;

// Crate
use crate::current_timestamp;
use crate::trim_trailing_zeros;
use crate::wallet::{
    EXEMPT_FEES_ADDRESSES, WALLET_FOUNDER, WALLET_PUBLIC_SALE, WALLET_STAKING, Wallet, find_wallet,
    is_valid_address,
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
    pub referrer: Option<String>,
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
    pub rate: u64,
    pub max_fee: u64,
    pub founder_percentage: u64,
    pub treasury_percentage: u64,
    pub staking_percentage: u64,
    pub referral_percentage: u64,
    pub referral_bonus: bool,
}

// Globals
pub const NANOSRKS_PER_SRKS: u64 = 1_000_000_000;
const PERCENT_BASE: u64 = 100_000;
const PREFIX_ADDRESS: &str = "SRKS_";

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
pub fn create_transaction(
    wallets: &Vec<Wallet>,
    ledger: &HashMap<String, u64>,
    sender: &str,
    recipient: &str,
    amount: u64,
    exempt_addresses: &HashSet<String>,
) -> Option<Transaction> {
    if !is_valid_address(sender) || !is_valid_address(recipient) {
        println!("Error : invalid address (must start with 'SRKS_').");
        return None;
    }

    let sender_wallet = find_wallet(wallets, sender);
    let recipient_wallet = find_wallet(wallets, recipient);

    // Set fees
    let fee_rule = FeeRule {
        rate: 1_000_u64,
        max_fee: 1 * NANOSRKS_PER_SRKS,
        founder_percentage: 40_000_u64,
        treasury_percentage: 30_000_u64,
        staking_percentage: 10_000_u64,
        referral_percentage: 20_000_u64,
        referral_bonus: false,
    };

    // Calculate fees
    let fee = if exempt_addresses.contains(sender) {
        0
    } else {
        (amount * fee_rule.rate / PERCENT_BASE).min(fee_rule.max_fee)
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

    // It's OK
    if !sender_wallet.is_none() && !recipient_wallet.is_none() {
        println!("The transaction was successfully completed");

        Some(Transaction {
            id: Uuid::new_v4(),
            sender: sender.to_string(),
            recipient: recipient.to_string(),
            amount,
            fee,
            fee_rule,
            timestamp: current_timestamp(),
            referrer: sender_wallet?.referrer.clone(),
        })
    }
    // Address not found
    else {
        if sender_wallet.is_none() {
            println!("Error : sender ({}) not found", sender);
        }
        if recipient_wallet.is_none() {
            println!("Error : recipient ({}) not found", recipient);
        }

        return None;
    }
}

// Fees distribution
fn distribute_fee(
    ledger: &mut HashMap<String, u64>,
    fee: u64,
    fee_rule: FeeRule,
    has_referrer: bool,
    referrer_wallet: Option<&String>,
) {
    // Distribution
    let percentages = [
        fee_rule.founder_percentage,
        fee_rule.treasury_percentage,
        fee_rule.staking_percentage,
        fee_rule.referral_percentage,
    ];

    let shares = split_fee_exact(fee, &percentages);

    // Update ledger
    *ledger.entry(WALLET_FOUNDER.to_string()).or_insert(0) += shares[0];
    *ledger.entry(WALLET_PUBLIC_SALE.to_string()).or_insert(0) += shares[1];
    *ledger.entry(WALLET_STAKING.to_string()).or_insert(0) += shares[2];

    // Check referrer
    if has_referrer {
        if let Some(referrer) = referrer_wallet {
            *ledger.entry(referrer.clone()).or_insert(0) += shares[3];
        } else {
            *ledger.entry(WALLET_FOUNDER.to_string()).or_insert(0) += shares[3];
        }
    } else {
        *ledger.entry(WALLET_FOUNDER.to_string()).or_insert(0) += shares[3];
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
pub fn distribute_initial_tokens(
    ledger: &mut Ledger,
    wallets: &Vec<Wallet>,
    blockchain: &mut Blockchain,
) {
    let distribution = vec![
        (
            format!("{}{}", PREFIX_ADDRESS, "sponsorship"),
            10_000_000 * NANOSRKS_PER_SRKS,
        ),
        (
            format!("{}{}", PREFIX_ADDRESS, "treasury"),
            10_000_000 * NANOSRKS_PER_SRKS,
        ),
    ];
    let mut transactions = Vec::new();

    for (recipient, amount) in distribution {
        if let Some(tx) = create_transaction(
            wallets,
            ledger,
            WALLET_PUBLIC_SALE,
            &recipient,
            amount,
            &EXEMPT_FEES_ADDRESSES,
        ) {
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
pub fn save_blockchain(blockchain: &Vec<Block>, filename: &str) {
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(filename)
        .expect("Error : unable to open output file");

    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &blockchain).expect("Error : serializing blockchain");
    println!("Blockchain saved in '{}'", filename);
}

// Load blockchain
pub fn load_blockchain(filename: &str) -> Vec<Block> {
    let file = File::open(filename);

    match file {
        Ok(f) => {
            let reader = BufReader::new(f);
            let blockchain: Vec<Block> = serde_json::from_reader(reader).unwrap_or_else(|_| {
                println!("Error : corrupt or empty file, initializing a new string");
                vec![]
            });
            println!("Blockchain loaded from '{}'", filename);
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

            let has_referrer = tx.referrer.is_some();
            distribute_fee(
                &mut ledger,
                tx.fee,
                tx.fee_rule.clone(),
                has_referrer,
                tx.referrer.as_ref(),
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

        let has_referrer = tx.referrer.is_some();
        distribute_fee(
            ledger,
            tx.fee,
            tx.fee_rule.clone(),
            has_referrer,
            tx.referrer.as_ref(),
        );

        true
    } else {
        false
    }
}

// Helpers
// -------

/*pub fn to_nanosrks(srks: f64) -> u64 {
    (srks * NANOSRKS_PER_SRKS as f64).round() as u64
}*/

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
