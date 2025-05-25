CREATE TABLE IF NOT EXISTS core.staking_scores (
    address TEXT NOT NULL,
    score BIGINT NOT NULL DEFAULT 0,
    completed BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (address)
);
