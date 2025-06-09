// Dependencies
use serde::{Deserialize, Serialize};
use serde_wasm_bindgen::to_value;
use wasm_bindgen::prelude::*;

// Modules
mod encryption;
mod handler;

// Crates
use crate::encryption::*;
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
#[derive(Serialize, Deserialize)]
pub struct SignatureStruct {
    pub signature: String,
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

// Create signature
#[wasm_bindgen]
pub fn create_signature(private_key: &str, message: &str) -> JsValue {
    let signaure_string =
        Encryption::create_signature(private_key.to_string(), message.to_string());
    let signature = SignatureStruct {
        signature: signaure_string.to_string(),
    };

    to_value(&signature).unwrap()
}

// Encryp memo
#[wasm_bindgen]
pub fn encrypt_memo(dh_public: &str, dh_secret: &str, memo: &str) -> JsValue {
    let memo_truncated = &memo[..memo.len().min(255)];
    let memo = Handler::encryption_memo(dh_secret, dh_public, memo_truncated);
    to_value(&memo.unwrap()).unwrap()
}

// Decrypt memo
#[wasm_bindgen]
pub fn decrypt_memo(dh_public: &str, dh_secret: &str, memo: &str) -> JsValue {
    match Handler::decryption_memo(dh_secret, dh_public, memo) {
        Ok(result) => JsValue::from_str(&result),
        Err(e) => {
            web_sys::console::error_1(&JsValue::from_str(&format!(
                "Decrypt error: {}",
                e.to_string()
            )));
            JsValue::from_str("")
        }
    }
}
