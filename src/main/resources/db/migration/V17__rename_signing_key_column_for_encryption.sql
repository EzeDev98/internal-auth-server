-- Step 14E: signing_key.private_key_pem now stores AES-256-GCM ciphertext
-- (see SecretEncryptionService), not a plain PEM - renamed to make that
-- honest at the schema level.
ALTER TABLE signing_key RENAME COLUMN private_key_pem TO encrypted_private_key;
