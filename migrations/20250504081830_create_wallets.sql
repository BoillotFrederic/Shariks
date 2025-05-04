CREATE TABLE IF NOT EXISTS wallets (
    address TEXT PRIMARY KEY,
    referrer TEXT,
    first_referrer BOOLEAN NOT NULL DEFAULT FALSE
);
