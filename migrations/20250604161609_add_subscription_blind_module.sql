-- Add a `blind_module` column to the subscriptions table.

-- There is nothing meaningful running so we don't care about data at this point.
DROP TABLE subscriptions;

CREATE TABLE subscriptions (
  public_key VARCHAR(66) NOT NULL,
  blind_module VARCHAR(100) NOT NULL,
  ends_at TIMESTAMP WITH TIME ZONE NOT NULL,
  PRIMARY KEY(public_key, blind_module)
);

