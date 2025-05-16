CREATE TABLE wallet_balances (
    address TEXT PRIMARY KEY,
    balance BIGINT NOT NULL DEFAULT 0
);
