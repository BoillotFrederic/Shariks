// Shariks Chain - Base du projet
// Langage : Rust

// Objectif : Initialiser le squelette d'une blockchain propriétaire avec PoR + PoS

// Crate de base à ajouter dans Cargo.toml :
// [dependencies]
// tokio = { version = "1", features = ["full"] }
// serde = { version = "1", features = ["derive"] }
// serde_json = "1"
// sha2 = "0.10"
// uuid = { version = "1", features = ["v4"] }

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Transaction {
    id: Uuid,
    sender: String,
    recipient: String,
    amount: f64,
    timestamp: u128,
    referral: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Block {
    index: u64,
    timestamp: u128,
    transactions: Vec<Transaction>,
    previous_hash: String,
    hash: String,
}

impl Block {
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

    fn calculate_hash(&self) -> String {
        let data = format!("{}{}{:?}{}", self.index, self.timestamp, self.transactions, self.previous_hash);
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }
}

fn current_timestamp() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()
}

fn main() {
    println!("Shariks Chain - Initialisation de la blockchain");
    
    // Bloc Genesis (exemple)
    let genesis_tx = Transaction {
        id: Uuid::new_v4(),
        sender: "genesis".to_string(),
        recipient: "founder_wallet_address".to_string(),
        amount: 100000000.0,
        timestamp: current_timestamp(),
        referral: None,
    };

    let genesis_block = Block::new(0, vec![genesis_tx], "0".to_string());

    println!("Bloc Genesis : {:?}", genesis_block);
}
