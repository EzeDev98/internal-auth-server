-- Renames the signing key column to hold the encrypted private key.
ALTER TABLE signing_key RENAME COLUMN private_key_pem TO encrypted_private_key;
