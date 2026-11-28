-- Adds the encrypted client secret column.
ALTER TABLE client_applications ADD COLUMN client_secret_encrypted TEXT;
