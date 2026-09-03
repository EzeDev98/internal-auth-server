-- Stage 2 punch-list item 4: formalize credential storage policy.
--
-- user_sessions.token was storing the raw bearer JWT in plaintext - anyone
-- with read access to this table could replay a live session's token and
-- impersonate that user for its remaining lifetime. Renamed to token_hash;
-- the application now stores/looks up a SHA-256 hash of the token instead
-- (see TokenHasher.java) - the JWT itself is never persisted. Shrunk from
-- VARCHAR(2000), sized for a raw JWT, to VARCHAR(255), which comfortably
-- fits a 64-character SHA-256 hex digest.
--
-- client_applications.client_secret is renamed to client_secret_hash to
-- make the "this must never hold a plaintext secret" contract explicit at
-- the schema level, matching users.password's naming precedent. It will
-- store a BCrypt hash via the same PasswordEncoder bean as users.password,
-- once something actually writes to it (Stage 3/4 - no code path creates a
-- ClientApplication row yet).

ALTER TABLE user_sessions RENAME COLUMN token TO token_hash;
ALTER TABLE user_sessions ALTER COLUMN token_hash TYPE VARCHAR(255);
ALTER TABLE user_sessions RENAME CONSTRAINT uk_user_sessions_token TO uk_user_sessions_token_hash;

ALTER TABLE client_applications RENAME COLUMN client_secret TO client_secret_hash;
