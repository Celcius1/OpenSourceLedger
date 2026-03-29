-- OSL: Sovereign Accounting System
-- Database Initialization Script v1.0
-- Copyright (C) 2026 Celsius Technical Services (AGPLv3)

-- 1. GLOBAL FOUNDATION
CREATE DOMAIN money_micro AS bigint;
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 2. MASTER REGISTRY
CREATE SCHEMA IF NOT EXISTS osl_registry;

CREATE TABLE osl_registry.tenants (
    tenant_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    schema_name     VARCHAR(64) UNIQUE NOT NULL,
    business_name   VARCHAR(255) NOT NULL,
    status          VARCHAR(20) DEFAULT 'ACTIVE',
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    ledger_pubkey   BYTEA NOT NULL
);

-- 3. TENANT TEMPLATE
CREATE SCHEMA IF NOT EXISTS osl_template;

-- A. The Chart of Accounts
CREATE TABLE osl_template.accounts (
    account_id      SERIAL PRIMARY KEY,
    code            VARCHAR(20) NOT NULL UNIQUE,
    name            VARCHAR(100) NOT NULL,
    type            VARCHAR(20) NOT NULL,
    tax_code        VARCHAR(20),
    is_system       BOOLEAN DEFAULT FALSE
);

-- B. The Immutable Ledger
CREATE TABLE osl_template.ledger_entries (
    entry_id        BIGSERIAL PRIMARY KEY,
    transaction_id  UUID NOT NULL,
    date            DATE NOT NULL,
    description     TEXT NOT NULL,
    account_id      INT REFERENCES osl_template.accounts(account_id),
    debit           money_micro DEFAULT 0,
    credit          money_micro DEFAULT 0,
    prev_hash       BYTEA,
    curr_hash       BYTEA,
    signature       BYTEA,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- C. Import Rules
CREATE TABLE osl_template.import_rules (
    rule_id         SERIAL PRIMARY KEY,
    priority        INT DEFAULT 50,
    regex_pattern   TEXT NOT NULL,
    target_acct_id  INT REFERENCES osl_template.accounts(account_id),
    tax_override    VARCHAR(20),
    description_new TEXT
);

-- D. Access Log
CREATE TABLE osl_template.access_log (
    log_id          BIGSERIAL PRIMARY KEY,
    timestamp       TIMESTAMPTZ DEFAULT NOW(),
    actor           VARCHAR(100),
    action          TEXT NOT NULL,
    metadata        JSONB
);
