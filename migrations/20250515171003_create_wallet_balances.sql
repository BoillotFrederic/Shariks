CREATE TABLE core.wallet_balances (
    address TEXT PRIMARY KEY,
    balance BIGINT NOT NULL DEFAULT 0
);
