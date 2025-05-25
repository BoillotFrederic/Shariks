CREATE TEMP TABLE tmp_ledger (
    address TEXT PRIMARY KEY,
    balance BIGINT NOT NULL DEFAULT 0
);
