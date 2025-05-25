CREATE TABLE core.system_status (
    id SERIAL PRIMARY KEY,
    genesis_done BOOLEAN NOT NULL DEFAULT FALSE,
    last_updated TIMESTAMP DEFAULT now()
);

INSERT INTO core.system_status (genesis_done) VALUES (FALSE);
