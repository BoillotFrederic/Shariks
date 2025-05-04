CREATE TABLE IF NOT EXISTS referrer_counter (
    referrer TEXT PRIMARY KEY,
    counter INTEGER NOT NULL DEFAULT 0
);
