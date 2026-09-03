CREATE TABLE signing_key (
    id BIGSERIAL PRIMARY KEY,
    kid VARCHAR(32) NOT NULL UNIQUE,
    private_key_pem TEXT NOT NULL,
    is_current BOOLEAN NOT NULL DEFAULT FALSE,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    retired_at TIMESTAMP
);

CREATE INDEX idx_signing_key_status ON signing_key (status);

-- At most one row can be the current signing key at any time.
CREATE UNIQUE INDEX idx_signing_key_current ON signing_key (is_current) WHERE is_current = TRUE;
