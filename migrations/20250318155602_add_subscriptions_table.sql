-- Add a subscriptions and payments tables

CREATE TABLE subscriptions (
  public_key VARCHAR(66) PRIMARY KEY,
  ends_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE TABLE payments (
  tx_hash VARCHAR(256) PRIMARY KEY,
  subscription_public_key VARCHAR(66) NOT NULL,
  validated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

