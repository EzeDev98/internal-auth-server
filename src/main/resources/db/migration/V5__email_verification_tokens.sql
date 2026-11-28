-- Adds the email verification token table.
CREATE TABLE email_verification_tokens (
    id         BIGSERIAL PRIMARY KEY,
    user_id    BIGINT NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used       BOOLEAN NOT NULL,
    created_at TIMESTAMP,
    used_at    TIMESTAMP,
    CONSTRAINT uk_email_verification_tokens_token_hash UNIQUE (token_hash),
    CONSTRAINT fk_email_verification_tokens_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);
CREATE INDEX idx_email_verification_tokens_user_id ON email_verification_tokens (user_id);
