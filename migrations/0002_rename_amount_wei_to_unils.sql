-- Rename amount_wei to amount_unils to reflect the NIL token's 6-decimal precision.
-- With 6 decimals, 1 unil (micro-NIL) equals 1 smallest token unit on-chain.
-- The previous "wei" naming incorrectly implied 18 decimals.

ALTER TABLE payments RENAME COLUMN amount_wei TO amount_unils;
