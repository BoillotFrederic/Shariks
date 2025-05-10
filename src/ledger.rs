// Dependencies
use std::collections::HashMap;

// Crates
use crate::Utils;
use crate::blockchain;
use crate::blockchain::*;

// Types
pub type LedgerMap = HashMap<String, u64>;

// Ledger
// ------

pub struct Ledger;
impl Ledger {
    // Initialize ledger from blockchain
    pub fn initialize_from_blockchain(blockchain: &Vec<blockchain::Block>) -> LedgerMap {
        let mut ledger: LedgerMap = HashMap::new();

        for block in blockchain {
            for tx in &block.transactions {
                if tx.sender != format!("{}{}", blockchain::PREFIX_ADDRESS, "genesis") {
                    *ledger.entry(tx.sender.clone()).or_insert(0) -= tx.amount + tx.fee;
                }

                *ledger.entry(tx.recipient.clone()).or_insert(0) += tx.amount;

                super::blockchain::Transaction::distribute_fee(
                    &mut ledger,
                    tx.fee,
                    tx.fee_rule.clone(),
                    tx.referrer.to_string(),
                );
            }
        }

        ledger
    }

    // Update ledger with block
    pub fn update_with_block(ledger: &mut LedgerMap, block: &Block) {
        for tx in &block.transactions {
            if !Self::apply_transaction(ledger, tx) {
                println!("Warning: transaction {:?} failed to apply", tx);
            }
        }
    }

    // Apply transaction
    pub fn apply_transaction(ledger: &mut LedgerMap, tx: &Transaction) -> bool {
        let sender_balance = ledger.get(&tx.sender).unwrap_or(&0);
        let total = tx.amount + tx.fee;
        let genesis = format!("{}{}", blockchain::PREFIX_ADDRESS, "genesis");

        if *sender_balance >= total || tx.sender == genesis {
            if tx.sender != genesis {
                *ledger.entry(tx.sender.clone()).or_insert(0) -= total;
            }
            *ledger.entry(tx.recipient.clone()).or_insert(0) += tx.amount;

            super::blockchain::Transaction::distribute_fee(
                ledger,
                tx.fee,
                tx.fee_rule.clone(),
                tx.referrer.to_string(),
            );

            true
        } else {
            false
        }
    }

    // View balances
    pub fn view_balances(ledger: &LedgerMap) {
        println!("\n--- Wallet balances ---");
        for (adresse, solde) in ledger.iter() {
            println!(
                "{} : {} SRKS",
                adresse,
                Utils::trim_trailing_zeros(blockchain::to_srks(*solde))
            );
        }
    }
}
