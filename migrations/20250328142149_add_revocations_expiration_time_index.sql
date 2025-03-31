-- Add an index on the revocations table to lookup by expiration time

CREATE INDEX revocations_expires_at ON revocations (expires_at);
