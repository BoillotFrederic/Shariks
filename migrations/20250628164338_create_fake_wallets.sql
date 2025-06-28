CREATE TABLE IF NOT EXISTS core.fake_wallets (
    public_key TEXT PRIMARY KEY,
    private_key TEXT,
    dh_public TEXT,
    dh_secret TEXT
);
