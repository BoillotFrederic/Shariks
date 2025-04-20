// Dependencies
// ------------
use serde::{Deserialize, Serialize}; // JSON
use sha2::{Digest, Sha256}; // HASH
use uuid::Uuid; // UNIQUE ID
use std::time::{SystemTime, UNIX_EPOCH}; // TIME

// Structures
// ----------

// Structure of a transaction
#[derive(Serialize, Deserialize, Debug, Clone)]
struct Transaction {
    id: Uuid,
    sender: String,
    recipient: String,
    amount: f64,
    timestamp: u128,
    referral: Option<String>,
}

// Structure of a block
#[derive(Serialize, Deserialize, Debug, Clone)]
struct Block {
    index: u64,
    timestamp: u128,
    transactions: Vec<Transaction>,
    previous_hash: String,
    hash: String,
}

// Structure of blockchain
#[derive(Debug)]
struct Blockchain {
    chain: Vec<Block>,
}

// Methods
// -------

// Block management
impl Block {

    // New block
    fn new(index: u64, transactions: Vec<Transaction>, previous_hash: String) -> Self {
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

    // Calculate HASH
    fn calculate_hash(&self) -> String {
        let data = format!("{}{}{:?}{}", self.index, self.timestamp, self.transactions, self.previous_hash);
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }
}


// Blockchain management
impl Blockchain {

    // First block
    fn new() -> Self {
        let genesis_tx = Transaction {
            id: Uuid::new_v4(),
            sender: "genesis".to_string(),
            recipient: "founder_wallet_address".to_string(),
            amount: 100000000.0,
            timestamp: current_timestamp(),
            referral: None,
        };

        let genesis_block = Block::new(0, vec![genesis_tx], "0".to_string());

        Blockchain {
            chain: vec![genesis_block],
        }
    }

    // Add block
    fn add_block(&mut self, transactions: Vec<Transaction>) {
        let last_block = self.chain.last().unwrap();
        let new_block = Block::new(
            last_block.index + 1,
            transactions,
            last_block.hash.clone(),
        );
        self.chain.push(new_block);
    }

    // Print
    fn print_chain(&self) {
        for block in &self.chain {
            println!("Index: {}", block.index);
            println!("Timestamp: {}", block.timestamp);
            println!("Hash: {}", block.hash);
            println!("Previous Hash: {}", block.previous_hash);
            println!("Transactions: {:#?}", block.transactions);
            println!("--------------------------");
        }
    }
}



// Current date in milliseconde
fn current_timestamp() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()
}

// main
// ----
fn main() {
    // Print init message
    println!("Shariks Chain - Initialisation de la blockchain");

    let mut blockchain = Blockchain::new();

    let tx1 = Transaction {
        id: Uuid::new_v4(),
        sender: "wallet_alice".to_string(),
        recipient: "wallet_bob".to_string(),
        amount: 250.0,
        timestamp: current_timestamp(),
        referral: Some("wallet_parrain".to_string()),
    };

    // Add block
    blockchain.add_block(vec![tx1]);

    // Print chain
    blockchain.print_chain();
}
