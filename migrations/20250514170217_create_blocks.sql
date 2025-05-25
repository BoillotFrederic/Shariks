CREATE TABLE core.blocks (
    index BIGINT PRIMARY KEY,
    timestamp BIGINT NOT NULL,
    previous_hash TEXT NOT NULL,
    hash TEXT NOT NULL,
    raw_json JSONB NOT NULL
);
