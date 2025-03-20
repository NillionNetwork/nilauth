-- Add a column to payments to indicate if they're valid.


-- First add the column, by default new payments are invalid.
ALTER TABLE payments
  ADD COLUMN is_valid boolean NOT NULL DEFAULT false;

-- However, existing payments should be marked as valid.
UPDATE payments SET is_valid = true;
