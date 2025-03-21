-- Add a column to payments to indicate if they're valid.

DROP TABLE payments;

CREATE TABLE payments (
  tx_hash VARCHAR(256) PRIMARY KEY,
  subscription_public_key VARCHAR(66) NOT NULL,
  validated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  is_valid boolean NOT NULL DEFAULT false
);


