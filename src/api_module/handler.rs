// Dependencies
use actix_web::{HttpResponse, Responder, web};
use serde::Deserialize;
use serde_json::json;

// Crates
use crate::blockchain;
use crate::encryption::*;
use crate::log::*;
use crate::wallet::*;
use sqlx::PgPool;

// Strucs
#[derive(Deserialize)]
pub struct CreateWalletPayload {
    pub referrer: String,
    pub passphrase: String,
    pub secure: Option<bool>,
}

// Handler
// -------

pub struct Handler;

impl Handler {
    // ---API handler---
    // -----------------

    /// Shariks API is running
    pub async fn health() -> impl Responder {
        HttpResponse::Ok().body("Shariks Chain API is running")
    }

    // ---Wallet handler---
    // --------------------

    /// Create a new wallet
    pub async fn new_wallet(
        payload: web::Json<CreateWalletPayload>,
        pg_pool: web::Data<PgPool>,
    ) -> impl Responder {
        let referrer_address = payload.referrer.trim();
        let passphrase = payload.passphrase.trim();
        let use_secure = payload.secure.unwrap_or(false);
        let referrer_found = Wallet::exists(&pg_pool, &referrer_address)
            .await
            .unwrap_or(false);

        if referrer_found || referrer_address.is_empty() {
            match Wallet::new(
                referrer_found,
                "",
                &referrer_address.trim(),
                &passphrase,
                false,
                true,
                &pg_pool,
            )
            .await
            {
                Ok((phrase, public_key, private_key, dh_public, dh_secret)) => {
                    let wallet_data = json!({
                        "mnemonic": phrase,
                        "public_key": public_key,
                        "private_key": private_key,
                        "dh_public": dh_public,
                        "dh_secret": dh_secret
                    });

                    if use_secure {
                        match Encryption::encrypt_json(&wallet_data, passphrase) {
                            payload => HttpResponse::Ok().json(payload),
                        }
                    } else {
                        HttpResponse::Ok().json(wallet_data)
                    }
                }
                Err(e) => {
                    Log::error(
                        "Handler",
                        "new_wallet",
                        "Failed to create wallet",
                        &e.to_string(),
                    );
                    HttpResponse::InternalServerError().body("Failed to create wallet")
                }
            }
        } else {
            HttpResponse::BadRequest().body("Invalid referrer wallet address")
        }
    }

    /// Recovery of a wallet
    pub async fn recovery_wallet() {}

    /// Create a new transaction from a wallet
    pub async fn create_transaction() {}

    /// View all transactions of a wallet
    pub async fn view_transactions() {}

    /// View a balance of a wallet
    pub async fn view_balance() {}

    /**/
    pub async fn view_blocks(pg_pool: web::Data<PgPool>) -> impl Responder {
        match blockchain::load_blocks_from_db(pg_pool.get_ref()).await {
            Ok(blocks) => HttpResponse::Ok().json(blocks),
            Err(e) => HttpResponse::InternalServerError().body(format!("DB error: {}", e)),
        }
    }

    pub async fn latest_block() -> impl Responder {
        // Placeholder - replace with real DB call
        HttpResponse::Ok().json(serde_json::json!({
            "block": "latest block hash placeholder"
        }))
    }

    // pub async fn wallet_balance(path: web::Path<String>) -> impl Responder {
    //     let address = path.into_inner();
    //     // Placeholder - replace with DB query
    //     HttpResponse::Ok().json(serde_json::json!({
    //         "wallet": address,
    //         "balance": 42.0
    //     }))
    // }
    /**/
}
