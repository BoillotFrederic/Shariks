// Dependencies
use serde::{Deserialize, Serialize};
use serde_wasm_bindgen::to_value;
use wasm_bindgen::prelude::*;

// Modules
mod encryption;
mod handler;

// Crates
use crate::handler::*;

// Structures
#[derive(Serialize, Deserialize)]
pub struct WalletStruct {
    pub phrase: String,
    pub public_key: String,
    pub private_key: String,
    pub dh_public: String,
    pub dh_secret: String,
}

// Genrate wallet
#[wasm_bindgen]
pub fn generate_wallet(passphrase: &str) -> JsValue {
    match Handler::new_wallet_keys(passphrase) {
        Ok((phrase, public_key, private_key, dh_public, dh_secret)) => {
            let wallet = WalletStruct {
                phrase,
                public_key,
                private_key,
                dh_public,
                dh_secret,
            };

            to_value(&wallet).unwrap()
        }
        Err(e) => JsValue::from_str(&format!("Error generate wallet : {}", e)),
    }
}

// Restore wallet
#[wasm_bindgen]
pub fn restore_wallet(phrase: &str, passphrase: &str) -> JsValue {
    match Handler::restore_wallet_keys(phrase, passphrase) {
        Ok((public_key, private_key, dh_public, dh_secret)) => {
            let wallet = WalletStruct {
                phrase: phrase.to_string(),
                public_key,
                private_key,
                dh_public,
                dh_secret,
            };

            to_value(&wallet).unwrap()
        }
        Err(e) => JsValue::from_str(&format!("Error restore wallet : {}", e)),
    }
}
