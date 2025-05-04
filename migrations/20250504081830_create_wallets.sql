CREATE TABLE IF NOT EXISTS wallets (
    address TEXT PRIMARY KEY,
    referrer TEXT,
    dh_public TEXT,
    first_referrer BOOLEAN NOT NULL DEFAULT FALSE
);
