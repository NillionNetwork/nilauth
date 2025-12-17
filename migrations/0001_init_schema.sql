-- Initial schema for nilauth with Ethereum ERC-20 payments.
-- This migration creates all tables for a fresh deployment.

-- Revocations table: tracks revoked NUC tokens
CREATE TABLE revocations (
    token_hash VARCHAR(64) PRIMARY KEY,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX revocations_expires_at ON revocations (expires_at);

-- Payments table: stores Ethereum payment transaction data
CREATE TABLE payments (
    tx_hash VARCHAR(66) PRIMARY KEY,
    chain_id BIGINT NOT NULL,
    amount_wei VARCHAR(78) NOT NULL,
    digest VARCHAR(66) NOT NULL,
    payer_address VARCHAR(42) NOT NULL,
    service_public_key VARCHAR(130) NOT NULL,
    blind_module VARCHAR(100) NOT NULL,
    payer_did VARCHAR(200) NOT NULL,
    subscriber_did VARCHAR(200) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    is_valid BOOLEAN NOT NULL DEFAULT false
);

CREATE INDEX payments_subscriber_did ON payments (subscriber_did);
CREATE INDEX payments_digest ON payments (digest);

-- Subscriptions table: tracks active subscriptions per DID and module
CREATE TABLE subscriptions (
    subscriber_did VARCHAR(200) NOT NULL,
    blind_module VARCHAR(100) NOT NULL,
    ends_at TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (subscriber_did, blind_module)
);

CREATE INDEX subscriptions_ends_at ON subscriptions (ends_at);
