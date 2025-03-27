-- Create a table to keep track of revocations

CREATE TABLE revocations (
  token_hash VARCHAR(64) PRIMARY KEY,
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  revoked_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
