// Dependencies
use actix_web::{HttpResponse, Responder, web};
use serde::Deserialize;
use serde_json::json;

// Crates
use shariks_core::blockchain;
use shariks_core::encryption::*;
use shariks_core::log::*;
use shariks_core::wallet::*;
use sqlx::PgPool;

// Strucs
#[derive(Deserialize)]
pub struct RegisterWalletPayload {
    pub public_key: String,
    pub dh_public: String,
    pub referrer: String,
}

#[derive(Deserialize)]
pub struct AddressPayload {
    pub address: String,
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

    // Wallet register
    pub async fn wallet_register(
        payload: web::Json<RegisterWalletPayload>,
        pg_pool: web::Data<PgPool>,
    ) -> impl Responder {
        let public_key = Wallet::add_prefix(payload.public_key.trim());
        let dh_public = payload.dh_public.trim();
        let mut referrer = payload.referrer.trim().to_string();

        // Vérifie si le wallet existe déjà
        match Wallet::exists(&pg_pool, &public_key).await {
            Ok(true) => {
                return HttpResponse::Conflict().body("The wallet already exists.");
            }
            Ok(false) => {
                let referrer_exists = Wallet::exists(&pg_pool, &referrer).await.unwrap_or(false);
                if !referrer_exists {
                    referrer.clear();
                }

                let success =
                    Wallet::register(referrer_exists, &referrer, &public_key, dh_public, &pg_pool)
                        .await;

                if success {
                    HttpResponse::Ok().json(serde_json::json!({ "register": true }))
                } else {
                    HttpResponse::InternalServerError().body("Error saving wallet.")
                }
            }
            Err(e) => {
                Log::error("Handler", "waller_register", "Check wallet", e);
                HttpResponse::InternalServerError().body("Erreur serveur.")
            }
        }
    }

    // Wallet register
    pub async fn wallet_exists(
        payload: web::Json<AddressPayload>,
        pg_pool: web::Data<PgPool>,
    ) -> impl Responder {
        let address = payload.address.trim();
        let success = Wallet::exists(&pg_pool, &address).await.unwrap_or(false);

        if success {
            HttpResponse::Ok().json(serde_json::json!({ "exists": true }))
        } else {
            HttpResponse::Ok().json(serde_json::json!({ "exists": false }))
        }
    }

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
