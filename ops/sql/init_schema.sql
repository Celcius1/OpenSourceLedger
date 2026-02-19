-- OSL: Sovereign Schema Initialization
-- Purpose: Creates the immutable ledger structure

CREATE SCHEMA IF NOT EXISTS osl_registry;

CREATE TABLE IF NOT EXISTS osl_registry.ledger_entries (
    id SERIAL PRIMARY KEY,
    transaction_uuid UUID DEFAULT gen_random_uuid(),
    account_code VARCHAR(10) NOT NULL,
    debit BIGINT NOT NULL DEFAULT 0,  -- Stored in Micros (1000000 = $1.00)
    credit BIGINT NOT NULL DEFAULT 0, -- Stored in Micros
    description TEXT NOT NULL,
    curr_hash CHAR(64) NOT NULL,      -- The SHA-256 Seal of this record
    prev_hash CHAR(64),               -- The Link to the previous record
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Index for rapid audit lookups
CREATE INDEX IF NOT EXISTS idx_ledger_hash ON osl_registry.ledger_entries(curr_hash);
CREATE INDEX IF NOT EXISTS idx_ledger_account ON osl_registry.ledger_entries(account_code);
