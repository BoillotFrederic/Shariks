// Dependencies
use actix_cors::Cors;
use actix_web::{App, HttpServer, web};
use dotenv::dotenv;
use shariks_core::log::*;
use sqlx::postgres::PgPoolOptions;
use std::env;
use std::io;

// Crates
use crate::handler::*;

// Modules
mod handler;

// Main
// ----

#[actix_web::main]
async fn main() -> io::Result<()> {
    // Start
    Log::info_msg("Main", "main", "Initialization start");

    // Read dotenv
    if let Err(e) = dotenvy::dotenv() {
        Log::warn("Main", "main", "Failed to load .env file", e);
    }

    // Connect to database
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|e| {
        Log::warn("Main", "main", "DATABASE_URL not found, using fallback", e);
        "".to_string()
    });
    let pg_pool = match PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
    {
        Ok(pool) => pool,
        Err(e) => {
            eprintln!("Failed to connect to database: {}", e);
            std::process::exit(1);
        }
    };

    // Read .env API
    dotenv().ok();
    let port = env::var("API_PORT").unwrap_or_else(|_| "8080".into());

    // Start
    println!("Shariks API is live on http://127.0.0.1:{}", port);

    HttpServer::new(move || {
        App::new()
            .wrap(
                Cors::default()
                    .allow_any_origin()
                    .allow_any_method()
                    .allow_any_header(),
            )
            // App data
            .app_data(web::Data::new(pg_pool.clone()))
            // health API
            .route("/health", web::get().to(Handler::health))
            // Register a new wallet
            .route("/wallet/register", web::post().to(Handler::wallet_register))
            // Check if wallet exists
            .route("/wallet/exists", web::post().to(Handler::wallet_exists))
            // Wallet find
            .route("/wallet/find", web::post().to(Handler::wallet_find))
            // Update wallet last_login
            .route(
                "/wallet/update_last_login",
                web::post().to(Handler::wallet_update_last_login),
            )
            // Update wallet dashboard
            .route(
                "/wallet/dashboard",
                web::post().to(Handler::dashbaord_wallet_data),
            )
            // Create a transaction
            .route(
                "/wallet/create_transaction",
                web::post().to(Handler::create_transaction),
            )
            // Get all transactions
            .route(
                "/wallet/get_transactions",
                web::post().to(Handler::get_transactions),
            )
            .route("/view_blocks", web::get().to(Handler::view_blocks))
            .route("/block/latest", web::get().to(Handler::latest_block))
        // .route(
        //     "/wallet/{address}/balance",
        //     web::get().to(Handler::wallet_balance),
        // )
    })
    .bind(format!("127.0.0.1:{}", port))?
    .run()
    .await
}
