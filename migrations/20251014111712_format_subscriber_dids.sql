-- Add `did:nil` prefix to existing hex-based subscriber public keys
UPDATE subscriptions
SET subscriber_did = 'did:nil:' || subscriber_did
WHERE subscriber_did NOT LIKE 'did:%';

UPDATE payments
SET subscriber_did = 'did:nil:' || subscriber_did
WHERE subscriber_did NOT LIKE 'did:%';
