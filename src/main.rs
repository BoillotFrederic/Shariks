// Dependencies
use serde::{Deserialize, Serialize};
use serde_json;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use std::io;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Write};

// Structures
#[derive(Serialize, Deserialize, Debug, Clone)]
struct Wallet {
    address: String,
    referrer: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Transaction {
    id: Uuid,
    sender: String,
    recipient: String,
    amount: f64,
    timestamp: u128,
    referrer: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Block {
    index: u64,
    timestamp: u128,
    transactions: Vec<Transaction>,
    previous_hash: String,
    hash: String,
}

#[derive(Debug)]
struct ReferralRegistry {
    referrals: HashMap<String, String>,
    known_wallets: Vec<String>,
}

// Blocks
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

// // Referral
// impl ReferralRegistry {
//     fn new() -> Self {
//         ReferralRegistry {
//             referrals: HashMap::new(),
//
//             // Test
//             known_wallets: vec![
//                 "wallet_parrain_1".to_string(),
//                 "wallet_parrain_2".to_string(),
//                 "wallet_filleul_1".to_string(),
//                 "wallet_filleul_2".to_string(),
//             ],
//         }
//     }
//
//     fn register_referral(&mut self, child: &str, parent: &str) -> bool {
//         if child == parent {
//             println!("Erreur : un utilisateur ne peut pas se parrainer lui-même.");
//             return false;
//         }
//         if self.referrals.contains_key(child) {
//             println!("Le filleul {} a déjà un parrain.", child);
//             return false;
//         }
//         if !self.known_wallets.contains(&parent.to_string()) {
//             println!("Le parrain {} n'est pas un wallet connu.", parent);
//             return false;
//         }
//         self.referrals.insert(child.to_string(), parent.to_string());
//         println!("Parrainage enregistré : {} → {}", parent, child);
//         true
//     }
//
//     fn get_referrer(&self, child: &str) -> Option<&String> {
//         self.referrals.get(child)
//     }
// }

// Current date
fn current_timestamp() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()
}

// Find a wallet
fn find_wallet(wallets: &Vec<Wallet>, address: &str) -> Option<Wallet> {
    wallets.iter().find(|w| w.address == address).cloned()
}

// Create a transaction
fn create_transaction(wallets: &Vec<Wallet>, sender: &str, recipient: &str, amount: f64) -> Option<Transaction> {
    let sender_wallet = find_wallet(wallets, sender)?;
    let recipient_wallet = find_wallet(wallets, recipient)?;

    Some(Transaction {
        id: Uuid::new_v4(),
        sender: sender.to_string(),
        recipient: recipient.to_string(),
        amount,
        timestamp: current_timestamp(),
        referrer: sender_wallet.referrer.clone(),
    })
}

// Save blockchain
fn save_blockchain(blockchain: &Vec<Block>, filename: &str) {
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(filename)
        .expect("Impossible d'ouvrir le fichier de sortie");

    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &blockchain).expect("Erreur lors de la sérialisation de la blockchain");
    println!("Blockchain sauvegardée dans '{}'", filename);
}

// Load blockchain
fn load_blockchain(filename: &str) -> Vec<Block> {
    let file = File::open(filename);

    match file {
        Ok(f) => {
            let reader = BufReader::new(f);
            let blockchain: Vec<Block> = serde_json::from_reader(reader).unwrap_or_else(|_| {
                println!("Fichier corrompu ou vide, initialisation d'une nouvelle chaîne.");
                vec![]
            });
            println!("Blockchain chargée depuis '{}'", filename);
            blockchain
        }
        Err(_) => {
            println!("Aucun fichier existant trouvé, création d'une nouvelle blockchain.");
            vec![]
        }
    }
}

// Get the latest HASH
fn get_latest_hash(blockchain: &Vec<Block>) -> String {
    if let Some(last_block) = blockchain.last() {
        last_block.hash.clone()
    } else {
        String::from("0")
    }
}

// Simple prompt
fn prompt(text: &str) -> String {
    println!("{}", text);
    let mut _prompt = String::new();
    io::stdin().read_line(&mut _prompt).expect("Erreur de lecture");
    _prompt.trim().to_string()
}

// Main
fn main() {
    println!("Shariks Chain - Initialisation de la blockchain");

    // Load bloackchain
    let filename = "blockchain.json";
    let mut blockchain = load_blockchain(filename);

    // Create wallets for test
    let wallets = vec![
        Wallet {
            address: "wallet_parrain_1".to_string(),
            referrer: None,
        },
        Wallet {
            address: "wallet_filleul_1".to_string(),
            referrer: Some("wallet_parrain_1".to_string()),
        },
        Wallet {
            address: "wallet_filleul_2".to_string(),
            referrer: Some("wallet_parrain_1".to_string()),
        },
    ];

    // Transaction GENESIS
    if blockchain.is_empty() {
        let genesis_tx = Transaction {
            id: Uuid::new_v4(),
            sender: "genesis".to_string(),
            recipient: "founder_wallet_address".to_string(),
            amount: 100000000.0,
            timestamp: current_timestamp(),
            referrer: None,
        };

        let genesis_block = Block::new(0, vec![genesis_tx], "0".to_string());
        blockchain.push(genesis_block.clone());
        save_blockchain(&blockchain, filename);
        println!("Bloc Genesis : {:?}", genesis_block);
    }

    // Transaction ask
    loop {
        println!("\n--- Menu ---");
        println!("1. Ajouter une transaction");
        println!("2. Voir les blocs");
        println!("3. Sauvegarder et quitter");

        let mut choice = String::new();
        io::stdin().read_line(&mut choice).expect("Erreur lecture");
        match choice.trim() {
            "1" => {
                let sender = prompt("Expéditeur :");
                let recipient = prompt("Destinataire :");
                let amount: f64 = prompt("Montant :").trim().parse().unwrap_or(0.0);

                if let Some(tx) = create_transaction(&wallets, &sender, &recipient, amount) {
                    let block = Block::new(1, vec![tx], get_latest_hash(&blockchain));
                    blockchain.push(block.clone());
                    println!("\nTransaction : {:?}", block);
                } else {
                    println!("Erreur : transaction invalide (adresse inconnue)");
                }
            }
            "2" => {
                for block in &blockchain {
                    println!("\n Bloc n°{} :", block.index);
                    println!("{:#?}", block);
                }
            }
            "3" => {
                save_blockchain(&blockchain, filename);
                println!("Au revoir !");
                break;
            }
            _ => println!("Choix invalide"),
        }
    }
}
