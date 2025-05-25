CREATE TABLE IF NOT EXISTS core.wallets (
    address TEXT PRIMARY KEY,
    referrer TEXT,
    dh_public TEXT,
    first_referrer BOOLEAN NOT NULL DEFAULT FALSE,
    referrer_count INTEGER NOT NULL DEFAULT 0,
    exempt_fee BOOLEAN NOT NULL DEFAULT FALSE,
    staking_available BOOLEAN NOT NULL DEFAULT TRUE,
    last_login TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);
