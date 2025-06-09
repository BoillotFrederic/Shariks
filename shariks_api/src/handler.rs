// Dependencies
use actix_web::{HttpResponse, Responder, web};
use serde::Deserialize;
use std::fs;
use std::time::Duration;

// Crates
use shariks_core::blockchain;
use shariks_core::encryption::*;
use shariks_core::ledger::*;
use shariks_core::log::*;
use shariks_core::utils::*;
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

#[derive(Deserialize)]
pub struct AddressStartPayload {
    pub address: String,
    pub start: u64,
}

#[derive(Deserialize)]
pub struct WalletUpdateLastLoginPayload {
    pub public_key: String,
    pub signature: String,
    pub message: String,
}

#[derive(Deserialize)]
pub struct TransactionPayload {
    pub sender: String,
    pub recipient: String,
    pub amount: f64,
    pub sender_dh_public: String,
    pub recipient_dh_public: String,
    pub memo: String,
    pub signature: String,
    pub message: String,
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

    /// Wallet register
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

    /// Wallet exists
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

    /// Update last_login
    pub async fn wallet_update_last_login(
        payload: web::Json<WalletUpdateLastLoginPayload>,
        pg_pool: web::Data<PgPool>,
    ) -> impl Responder {
        let public_key = payload.public_key.trim();
        let signature = payload.signature.trim();
        let message = payload.message.trim();

        let success = Encryption::verify_signature(&public_key, &message, &signature);

        if success {
            let updated =
                match Wallet::update_last_login(&pg_pool, &Wallet::add_prefix(&public_key)).await {
                    Ok(_) => true,
                    Err(_e) => false,
                };

            HttpResponse::Ok().json(serde_json::json!({
                "status": "ok",
                "updated": updated
            }))
        } else {
            HttpResponse::Ok().json(serde_json::json!({
                "status": "ko",
                "updated": false
            }))
        }
    }

    /// Get all info for wallet dashboard
    pub async fn dashbaord_wallet_data(
        payload: web::Json<AddressPayload>,
        pg_pool: web::Data<PgPool>,
    ) -> impl Responder {
        let address = payload.address.trim();
        let cache_path = format!("cache/{}.json", address);

        if let Ok(metadata) = fs::metadata(&cache_path) {
            if let Ok(modified) = metadata.modified() {
                if modified.elapsed().unwrap_or(Duration::from_secs(61)) < Duration::from_secs(60) {
                    if let Ok(contents) = fs::read_to_string(&cache_path) {
                        return HttpResponse::Ok()
                            .content_type("application/json")
                            .body(contents);
                    }
                }
            }
        }

        let wallet = Wallet::find(&pg_pool, address).await;
        let balance =
            blockchain::to_srks(Ledger::get_balance(&pg_pool, &address).await.unwrap_or(0));
        let ((incoming, incoming_count), (outgoing, outgoing_count)) =
            match blockchain::Transaction::get_totals_inout(&pg_pool, address).await {
                Ok(v) => v,
                Err(_) => ((0.0, 0), (0.0, 0)),
            };

        let (referrer_count, referrer) = match wallet {
            Ok(w) => (
                w.referrer_count as u64,
                w.referrer.unwrap_or_else(|| "".to_string()),
            ),
            Err(_) => (0, "".to_string()),
        };
        let staking_rewards =
            match blockchain::Transaction::get_staking_rewards(&pg_pool, address).await {
                Ok(s) => s as u64,
                Err(_) => 0,
            };
        let fee_rewards = match blockchain::Transaction::get_fee_rewards(&pg_pool, address).await {
            Ok(f) => f,
            Err(_) => 0.0,
        };
        let fee_transaction =
            match blockchain::Transaction::get_fee_transaction(&pg_pool, address).await {
                Ok(f) => f,
                Err(_) => 0.0,
            };

        let response = serde_json::json!({
            "status": "ok",
            "balance": balance,
            "incoming": incoming,
            "outgoing": outgoing,
            "incoming_count": incoming_count,
            "outgoing_count": outgoing_count,
            "referrer_count": referrer_count,
            "referrer": referrer,
            "staking_rewards": staking_rewards,
            "fee": blockchain::FEE_RATE as f64 / blockchain::PERCENT_BASE as f64,
            "fee_rewards": fee_rewards,
            "fee_transaction": fee_transaction
        });

        let _ = fs::create_dir_all("cache");
        let _ = fs::write(&cache_path, serde_json::to_string(&response).unwrap());

        HttpResponse::Ok().json(response)
    }

    /// Find a wallet data
    pub async fn wallet_find(
        payload: web::Json<AddressPayload>,
        pg_pool: web::Data<PgPool>,
    ) -> impl Responder {
        let address = payload.address.trim();
        let wallet = Wallet::find(&pg_pool, address).await;
        let wallet_status = match wallet {
            Ok(_) => "OK",
            Err(_) => "KO",
        };

        HttpResponse::Ok().json(serde_json::json!({
            "status": wallet_status,
            "wallet": wallet.unwrap()
        }))
    }

    /// Create a new transaction from a wallet
    pub async fn create_transaction(
        payload: web::Json<TransactionPayload>,
        pg_pool: web::Data<PgPool>,
    ) -> impl Responder {
        let sender = payload.sender.trim();
        let recipient = payload.recipient.trim();
        let amount = payload.amount;
        let sender_dh_public_str = payload.sender_dh_public.trim();
        let recipient_dh_public_str = payload.recipient_dh_public.trim();
        let memo = payload.memo.trim();
        let signature = payload.signature.trim();
        let message = payload.message.trim();

        let tx = match blockchain::Transaction::create(
            sender,
            recipient,
            blockchain::to_nanosrks(amount),
            sender_dh_public_str,
            recipient_dh_public_str,
            memo,
            signature,
            message,
            &pg_pool,
        )
        .await
        {
            Some(tx) => tx,
            None => {
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "status": "KO",
                    "error": "Transaction creation failed (None returned)"
                }));
            }
        };

        let (last_index, last_hash) = match blockchain::Block::get_last_block_meta(&pg_pool).await {
            Ok(v) => v,
            Err(e) => {
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "status": "KO",
                    "error": format!("Failed to get last block: {}", e)
                }));
            }
        };

        let block = blockchain::Block::new(last_index + 1, vec![tx.clone()], last_hash);

        let mut tx_db = match pg_pool.begin().await {
            Ok(t) => t,
            Err(e) => {
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "status": "KO",
                    "error": format!("Failed to begin transaction: {}", e)
                }));
            }
        };

        let result = async {
            blockchain::Block::save_to_db(&block, &mut tx_db).await?;
            blockchain::Transaction::save_to_db(&tx, block.index, &mut tx_db).await?;
            Ledger::apply_transaction(&tx, &mut tx_db).await?;
            Ok::<(), Box<dyn std::error::Error>>(())
        }
        .await;

        match result {
            Ok(_) => {
                if let Err(e) = tx_db.commit().await {
                    return HttpResponse::InternalServerError().json(serde_json::json!({
                        "status": "KO",
                        "error": format!("Failed to commit: {}", e)
                    }));
                }

                Log::info_msg("Main", "main", "The transaction was successfully completed");

                Utils::file_safe_delete(&format!("cache/{}.json", sender));
                Utils::file_safe_delete(&format!("cache/{}.json", recipient));

                HttpResponse::Ok().json(serde_json::json!({
                    "status": "OK",
                    "block_index": block.index,
                    "tx_id": tx.id,
                }))
            }
            Err(e) => {
                let _ = tx_db.rollback().await;
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "status": "KO",
                    "error": format!("Transaction failed: {}", e)
                }))
            }
        }
    }

    /// View transactions of a wallet
    pub async fn get_transactions(
        payload: web::Json<AddressStartPayload>,
        pg_pool: web::Data<PgPool>,
    ) -> impl Responder {
        let address = payload.address.trim();
        let start = payload.start;

        match blockchain::Transaction::get_all_transactions(&pg_pool, &address, start).await {
            Ok(t) => HttpResponse::Ok().json(serde_json::json!({
                "status": "OK",
                "transactions": t
            })),
            Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
                "status": "KO",
                "error": format!("Get transactions failed: {}", e)
            })),
        }
    }

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
