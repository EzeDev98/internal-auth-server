-- Stores session tokens and client secrets as hashes.
ALTER TABLE user_sessions RENAME COLUMN token TO token_hash;
ALTER TABLE user_sessions ALTER COLUMN token_hash TYPE VARCHAR(255);
ALTER TABLE user_sessions RENAME CONSTRAINT uk_user_sessions_token TO uk_user_sessions_token_hash;

ALTER TABLE client_applications RENAME COLUMN client_secret TO client_secret_hash;
