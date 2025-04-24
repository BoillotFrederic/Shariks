// Dependencies
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use once_cell::sync::Lazy;

// Structures
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Wallet {
    pub address: String,
    pub referrer: Option<String>,
}

/*#[derive(Debug)]
struct ReferralRegistry {
    referrals: HashMap<String, String>,
    known_wallets: Vec<String>,
}*/

// Global
pub const WALLET_GENESIS : &str = "SRKS_genesis";
pub const WALLET_PUBLIC_SALE : &str = "SRKS_public_sale";
pub const WALLET_FOUNDER : &str = "SRKS_NeoDev";
pub const WALLET_SPONSORSHIP : &str = "SRKS_sponsorship";
pub const WALLET_STAKING : &str = "SRKS_staking";
pub const WALLET_TREASURY : &str = "SRKS_treasury";

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

// Find a wallet
pub fn find_wallet(wallets: &Vec<Wallet>, address: &str) -> Option<Wallet> {
    wallets.iter().find(|w| w.address == address).cloned()
}

// Check wallet
pub fn is_valid_address(address: &str) -> bool {
    address.starts_with("SRKS_")
}

/*
// Referral
// --------
impl ReferralRegistry {
    fn new() -> Self {
        ReferralRegistry {
            referrals: HashMap::new(),

            // Test
            known_wallets: vec![
                "wallet_parrain_1".to_string(),
                "wallet_parrain_2".to_string(),
                "wallet_filleul_1".to_string(),
                "wallet_filleul_2".to_string(),
            ],
        }
    }

    fn register_referral(&mut self, child: &str, parent: &str) -> bool {
        if child == parent {
            println!("Erreur : un utilisateur ne peut pas se parrainer lui-même.");
            return false;
        }
        if self.referrals.contains_key(child) {
            println!("Le filleul {} a déjà un parrain.", child);
            return false;
        }
        if !self.known_wallets.contains(&parent.to_string()) {
            println!("Le parrain {} n'est pas un wallet connu.", parent);
            return false;
        }
        self.referrals.insert(child.to_string(), parent.to_string());
        println!("Parrainage enregistré : {} → {}", parent, child);
        true
    }

    fn get_referrer(&self, child: &str) -> Option<&String> {
        self.referrals.get(child)
    }
}*/
