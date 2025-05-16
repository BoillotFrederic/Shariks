CREATE TABLE transactions (
    id UUID PRIMARY KEY,
    block_index BIGINT NOT NULL REFERENCES blocks(index),
    sender TEXT NOT NULL,
    recipient TEXT NOT NULL,
    amount BIGINT NOT NULL,
    fee BIGINT NOT NULL,
    fee_founder INTEGER NOT NULL,
    fee_treasury INTEGER NOT NULL,
    fee_staking INTEGER NOT NULL,
    fee_referral INTEGER NOT NULL,
    timestamp BIGINT NOT NULL,
    signature TEXT,
    referrer TEXT,
    sender_dh_public TEXT,
    recipient_dh_public TEXT,
    memo TEXT
);
