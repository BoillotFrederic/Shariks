// Dependencies
use serde::{Deserialize, Serialize};
use serde_json;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use once_cell::sync::Lazy;
use std::collections::HashSet;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use std::io;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter/*, Write*/};

// Type
type Ledger = HashMap<String, f64>;
type Blockchain = Vec<Block>;

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
    fee: f64,
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

// Global
const WALLET_GENESIS : &str = "SRKS_genesis";
const WALLET_PUBLIC_SALE : &str = "SRKS_public_sale";
const WALLET_FOUNDER : &str = "SRKS_NeoDev";
const WALLET_SPONSORSHIP : &str = "SRKS_sponsorship";
const WALLET_STAKING : &str = "SRKS_staking";
const WALLET_TREASURY : &str = "SRKS_treasury";

pub static EXEMPT_FEES_ADDRESSES: Lazy<HashSet<String>> = Lazy::new(|| {
    vec![
        WALLET_GENESIS.to_string(),
        WALLET_PUBLIC_SALE.to_string(),
        WALLET_FOUNDER.to_string(),
        WALLET_STAKING.to_string(),
        WALLET_SPONSORSHIP.to_string(),
        WALLET_TREASURY.to_string(),
    ]
    .into_iter()
    .collect()
});

/*#[derive(Debug)]
struct ReferralRegistry {
    referrals: HashMap<String, String>,
    known_wallets: Vec<String>,
}*/

// Blockchain
// ----------

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

    // HASH
    fn calculate_hash(&self) -> String {
        let data = format!("{}{}{:?}{}", self.index, self.timestamp, self.transactions, self.previous_hash);
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }
}

// Create a transaction
fn create_transaction(wallets: &Vec<Wallet>, ledger: &HashMap<String, f64>, sender: &str, recipient: &str, amount: f64, exempt_addresses: &HashSet<String>,) -> Option<Transaction> {
    if !is_valid_address(sender) || !is_valid_address(recipient) {
        println!("Erreur : adresse invalide (doit commencer par 'SRKS_').");
        return None;
    }

    let sender_wallet = find_wallet(wallets, sender);
    let recipient_wallet = find_wallet(wallets, recipient);

    // Calculate fees
    let fee = if exempt_addresses.contains(sender) {
        0.0
    } else {
        (amount * 0.01).min(1.0)
    };

    let total = amount + fee;

    // Sold out
    if sender != "SRKS_genesis" {
        let balance = ledger.get(sender).unwrap_or(&0.0);
        if *balance < total {
            println!(
                "Erreur : solde insuffisant. Solde actuel de {} : {}, requis : {}",
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
            timestamp: current_timestamp(),
            referrer: sender_wallet?.referrer.clone(),
        })
    }
    // Address not found
    else {
        if sender_wallet.is_none() {
            println!("Sender ({}) not found", sender);
        }
        if recipient_wallet.is_none() {
            println!("Recipient ({}) not found", recipient);
        }

        return None;
    }
}

// Fees distribution
fn distribute_fee(ledger: &mut HashMap<String, f64>, fee: f64, has_referrer: bool, referrer_wallet: Option<&String>,) {
    let founder_share = fee * 0.40;
    let treasury_share = fee * 0.30;
    let staking_share = fee * 0.10;
    let referral_share = fee * 0.20;

    *ledger.entry(WALLET_FOUNDER.to_string()).or_insert(0.0) += founder_share;
    *ledger.entry(WALLET_PUBLIC_SALE.to_string()).or_insert(0.0) += treasury_share;
    *ledger.entry(WALLET_STAKING.to_string()).or_insert(0.0) += staking_share;

    if has_referrer {
        if let Some(referrer) = referrer_wallet {
            *ledger.entry(referrer.clone()).or_insert(0.0) += referral_share;
        } else {
            *ledger.entry(WALLET_FOUNDER.to_string()).or_insert(0.0) += referral_share;
        }
    } else {
        *ledger.entry(WALLET_FOUNDER.to_string()).or_insert(0.0) += referral_share;
    }
}

fn distribute_initial_tokens(ledger: &mut Ledger, wallets: &Vec<Wallet>, blockchain: &mut Blockchain) {
    let genesis = WALLET_PUBLIC_SALE;
    let distribution = vec![
        ("SRKS_sponsorship", 10_000_000.0),
        ("SRKS_treasury", 10_000_000.0),
    ];
    let mut transactions = Vec::new();

    for (recipient, amount) in distribution {
        if let Some(tx) = create_transaction(wallets, ledger, genesis, recipient, amount, &EXEMPT_FEES_ADDRESSES) {
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

// ledger
// ------

// Initialize ledger
fn initialize_ledger_from_blockchain(blockchain: &Vec<Block>) -> HashMap<String, f64> {
    let mut ledger: HashMap<String, f64> = HashMap::new();

    for block in blockchain {
        for tx in &block.transactions {
            if tx.sender != "SRKS_genesis" {
                *ledger.entry(tx.sender.clone()).or_insert(0.0) -= tx.amount + tx.fee;
            }

            *ledger.entry(tx.recipient.clone()).or_insert(0.0) += tx.amount;

            let has_referrer = tx.referrer.is_some();
            distribute_fee(&mut ledger, tx.fee, has_referrer, tx.referrer.as_ref());
        }
    }

    ledger
}

// Update ledger
fn update_ledger_with_block(ledger: &mut HashMap<String, f64>, block: &Block) {
    for tx in &block.transactions {
        if tx.sender != "SRKS_genesis" {
            *ledger.entry(tx.sender.clone()).or_insert(0.0) -= tx.amount + tx.fee;
        }
        *ledger.entry(tx.recipient.clone()).or_insert(0.0) += tx.amount;

        let has_referrer = tx.referrer.is_some();
        distribute_fee(ledger, tx.fee, has_referrer, tx.referrer.as_ref());
    }
}

fn apply_transaction(ledger: &mut Ledger, tx: &Transaction,) -> bool {
    let sender_balance = ledger.get(&tx.sender).unwrap_or(&0.0);
    let total = tx.amount + tx.fee;

    if *sender_balance >= total {
        *ledger.entry(tx.sender.clone()).or_insert(0.0) -= total;
        *ledger.entry(tx.recipient.clone()).or_insert(0.0) += tx.amount;

        let has_referrer = tx.referrer.is_some();
        distribute_fee(ledger, tx.fee, has_referrer, tx.referrer.as_ref());

        true
    } else {
        false
    }
}

// fn apply_transaction(ledger: &mut HashMap<String, f64>, tx: &Transaction, has_referrer: bool, referrer_wallet: Option<&String>,) {
//     let sender_balance = ledger.entry(tx.sender.clone()).or_insert(0.0);
//
//     if *sender_balance >= tx.amount + tx.fee {
//         *sender_balance -= tx.amount + tx.fee;
//         let recipient_balance = ledger.entry(tx.recipient.clone()).or_insert(0.0);
//         *recipient_balance += tx.amount;
//
//         distribute_fee(ledger, tx.fee, has_referrer, referrer_wallet);
//     }
// }

// Referral
// --------

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

// Tools
// -----

// Get the latest HASH
fn get_latest_hash(blockchain: &Vec<Block>) -> String {
    if let Some(last_block) = blockchain.last() { last_block.hash.clone() }
    else { String::from("0") }
}

// Simple prompt
fn prompt(text: &str) -> String {
    println!("{}", text);
    let mut _prompt = String::new();
    io::stdin().read_line(&mut _prompt).expect("Erreur de lecture");
    _prompt.trim().to_string()
}

// Get soldes
fn view_balances(ledger: &HashMap<String, f64>) {
    println!("\n--- Soldes des wallets ---");
    for (adresse, solde) in ledger.iter() {
        println!("{} : {:.2} SRKS", adresse, solde);
    }
}

// Current date
fn current_timestamp() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()
}

// Find a wallet
fn find_wallet(wallets: &Vec<Wallet>, address: &str) -> Option<Wallet> {
    wallets.iter().find(|w| w.address == address).cloned()
}

// Check wallet
fn is_valid_address(address: &str) -> bool {
    address.starts_with("SRKS_")
}

// Main
fn main() {
    println!("Shariks Chain - Initialisation de la blockchain");

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
        let genesis_tx = Transaction {
            id: Uuid::new_v4(),
            sender: WALLET_GENESIS.to_string(),
            recipient: WALLET_PUBLIC_SALE.to_string(),
            amount: 100000000.0,
            fee: 0.0,
            timestamp: current_timestamp(),
            referrer: None,
        };

        let genesis_block = Block::new(0, vec![genesis_tx], "0".to_string());
        blockchain.push(genesis_block.clone());
        update_ledger_with_block(&mut ledger, &genesis_block);
        println!("Bloc Genesis : {:?}", genesis_block);

        // Transaction of distribution initial
        distribute_initial_tokens(&mut ledger, &wallets, &mut blockchain);

        // First block chain save
        save_blockchain(&blockchain, filename);
    }

    // Transaction ask
    loop {
        println!("\n--- Menu ---");
        println!("1. Ajouter une transaction");
        println!("2. Voir les blocs");
        println!("3. Afficher les soldes");
        println!("4. Sauvegarder et quitter");

        let mut choice = String::new();
        io::stdin().read_line(&mut choice).expect("Erreur lecture");
        match choice.trim() {
            "1" => {
                let sender = prompt("Expéditeur :");
                let recipient = prompt("Destinataire :");
                let amount: f64 = prompt("Montant :").trim().parse().unwrap_or(0.0);

                if let Some(tx) = create_transaction(&wallets, &ledger, &sender, &recipient, amount, &EXEMPT_FEES_ADDRESSES) {
                    let block = Block::new(blockchain.len() as u64, vec![tx], get_latest_hash(&blockchain));
                    update_ledger_with_block(&mut ledger, &block);
                    blockchain.push(block.clone());
                    println!("\nTransaction : {:?}", block);
                }
            }
            "2" => {
                for block in &blockchain {
                    println!("\n Bloc n°{} :", block.index);
                    println!("{:#?}", block);
                }
            }
            "3" => {
                view_balances(&ledger);
            }
            "4" => {
                save_blockchain(&blockchain, filename);
                println!("Au revoir !");
                break;
            }
            _ => println!("Choix invalide"),
        }
    }
}
