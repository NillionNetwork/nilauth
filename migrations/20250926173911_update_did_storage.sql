-- Rename and resize columns to store full Did strings instead of just public keys.
ALTER TABLE subscriptions
    RENAME COLUMN public_key TO subscriber_did;
ALTER TABLE subscriptions
    ALTER COLUMN subscriber_did TYPE VARCHAR(128);

ALTER TABLE payments
    RENAME COLUMN subscription_public_key TO subscriber_did;
ALTER TABLE payments
    ALTER COLUMN subscriber_did TYPE VARCHAR(128);
