// Dependencies
use serde::{Deserialize, Serialize};
use serde_json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter};
use uuid::Uuid;

// Crate
use crate::current_timestamp;
use crate::trim_trailing_zeros;
use crate::wallet::{
    EXEMPT_FEES_ADDRESSES, Wallet, create_new_wallet, find_wallet, is_valid_address,
    load_wallet_owner, save_wallet_to_file,
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
    pub referrer: String,
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
            referrer: sender_wallet?.referrer,
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
    if has_referrer {
        if !referrer_wallet.is_empty() {
            *ledger.entry(referrer_wallet.to_string()).or_insert(0) += shares[3];
        } else {
            *ledger.entry(founder_address).or_insert(0) += shares[3];
        }
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
pub fn distribute_initial_tokens(
    ledger: &mut Ledger,
    wallets: &mut Vec<Wallet>,
    blockchain: &mut Blockchain,
) {
    // Public sale
    let public_sale_wallet = load_wallet_owner(format!("first_set\\{}", "PUBLIC_SALE"));
    let local_sale_wallet = Wallet {
        address: format!("SRKS_{}", public_sale_wallet.public_key.to_string()),
        referrer: "".to_string(),
        first_referrer: false,
    };

    // Create founder wallet
    let founder_wallet = create_new_wallet(false, "FOUNDER".to_string(), "");
    save_wallet_to_file(&founder_wallet, &founder_wallet.address);
    let _founder_wallet = load_wallet_owner(format!("first_set\\{}", "FOUNDER"));
    let local_founder_wallet = Wallet {
        address: format!("SRKS_{}", _founder_wallet.public_key.to_string()),
        referrer: "".to_string(),
        first_referrer: false,
    };

    // Create sponsorship wallet
    let sponsorship_wallet = create_new_wallet(false, "SPONSORSHIP".to_string(), "");
    save_wallet_to_file(&sponsorship_wallet, &sponsorship_wallet.address);
    let _sponsorship_wallet = load_wallet_owner(format!("first_set\\{}", "SPONSORSHIP"));
    let local_wallet_sponsorship = Wallet {
        address: format!("SRKS_{}", _sponsorship_wallet.public_key.to_string()),
        referrer: "".to_string(),
        first_referrer: false,
    };

    // Create treasury wallet
    let treasury_wallet = create_new_wallet(false, "TREASURY".to_string(), "");
    save_wallet_to_file(&treasury_wallet, &treasury_wallet.address);
    let _treasury_wallet = load_wallet_owner(format!("first_set\\{}", "TREASURY"));
    let local_wallet_treasury = Wallet {
        address: format!("SRKS_{}", _treasury_wallet.public_key.to_string()),
        referrer: "".to_string(),
        first_referrer: false,
    };

    // Create staking wallet
    let staking_wallet = create_new_wallet(false, "STAKING".to_string(), "");
    save_wallet_to_file(&staking_wallet, &staking_wallet.address);
    let _staking_wallet = load_wallet_owner(format!("first_set\\{}", "STAKING"));
    let local_staking_wallet = Wallet {
        address: format!("SRKS_{}", _staking_wallet.public_key.to_string()),
        referrer: "".to_string(),
        first_referrer: false,
    };

    let mut addresses = EXEMPT_FEES_ADDRESSES.lock().unwrap();
    addresses.insert(local_sale_wallet.clone().address);
    addresses.insert(local_founder_wallet.clone().address);
    addresses.insert(local_wallet_sponsorship.clone().address);
    addresses.insert(local_staking_wallet.clone().address);
    addresses.insert(local_wallet_treasury.clone().address);

    wallets.push(local_sale_wallet);
    wallets.push(local_founder_wallet);
    wallets.push(local_wallet_sponsorship);
    wallets.push(local_staking_wallet);
    wallets.push(local_wallet_treasury);

    let distribution = vec![
        (
            format!("SRKS_{}", _sponsorship_wallet.public_key),
            10_000_000 * NANOSRKS_PER_SRKS,
        ),
        (
            format!("SRKS_{}", _treasury_wallet.public_key),
            10_000_000 * NANOSRKS_PER_SRKS,
        ),
    ];
    let mut transactions = Vec::new();

    for (recipient, amount) in distribution {
        if let Some(tx) = create_transaction(
            wallets,
            ledger,
            &format!("SRKS_{}", public_sale_wallet.public_key),
            &recipient,
            amount,
            &addresses,
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

            //let has_referrer = tx.referrer.is_some();
            distribute_fee(
                &mut ledger,
                tx.fee,
                tx.fee_rule.clone(),
                /*has_referrer*/ !tx.referrer.is_empty(),
                tx.referrer.to_string(), //tx.referrer.as_ref(),
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

        //let has_referrer = tx.referrer.is_some();
        distribute_fee(
            ledger,
            tx.fee,
            tx.fee_rule.clone(),
            /*has_referrer*/ !tx.referrer.is_empty(),
            tx.referrer.to_string(), //tx.referrer.as_ref(),
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
