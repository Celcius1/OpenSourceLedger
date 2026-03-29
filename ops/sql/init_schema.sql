-- OSL: Sovereign Schema Initialization
-- Purpose: Creates the immutable ledger structure

DROP TABLE IF EXISTS ledger CASCADE;

CREATE TABLE ledger (
    id SERIAL PRIMARY KEY,
    transaction_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    description TEXT NOT NULL,
    debit_micros BIGINT NOT NULL DEFAULT 0,
    credit_micros BIGINT NOT NULL DEFAULT 0,
    balance_micros BIGINT NOT NULL DEFAULT 0,
    category VARCHAR(100),
    sub_category VARCHAR(100),
    division_id VARCHAR(50) DEFAULT 'global',
    status VARCHAR(20) DEFAULT 'ACTIVE',
    row_hash CHAR(64) NOT NULL
);

-- Indexes for rapid audit lookups
CREATE INDEX idx_ledger_hash ON ledger(row_hash);
CREATE INDEX idx_ledger_division ON ledger(division_id);
