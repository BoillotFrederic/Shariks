// Dependencies
use actix_web::{App, HttpServer, web};
use dotenv::dotenv;
use shariks::api_module::handler::*;
use shariks::log::*;
use sqlx::postgres::PgPoolOptions;
use std::env;
use std::io;

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
            // App data
            .app_data(web::Data::new(pg_pool.clone()))
            // health API
            .route("/health", web::get().to(Handler::health))
            // Create a new wallet
            .route("/wallet/create", web::post().to(Handler::new_wallet))
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
