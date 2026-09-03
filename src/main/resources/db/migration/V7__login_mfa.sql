-- Step 11E: opt-in login MFA (SMS OTP step-up), reusing the same OTP
-- machinery password reset uses (OtpResetEngine/OtpService). mfa_enabled
-- defaults false - existing accounts are unaffected until an admin turns
-- it on (see MfaAdminController for why this is admin-toggled, not
-- self-service, for now).

ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE login_mfa_otps (
    id             BIGSERIAL PRIMARY KEY,
    user_id        BIGINT NOT NULL,
    phone_number   VARCHAR(255) NOT NULL,
    otp_hash       VARCHAR(255) NOT NULL,
    expires_at     TIMESTAMP NOT NULL,
    attempt_count  INTEGER NOT NULL,
    max_attempts   INTEGER NOT NULL,
    status         VARCHAR(255) NOT NULL,
    created_at     TIMESTAMP,
    verified_at    TIMESTAMP,
    invalidated_at TIMESTAMP,
    last_sent_at   TIMESTAMP,
    CONSTRAINT fk_login_mfa_otps_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);
CREATE INDEX idx_login_mfa_otps_user_id ON login_mfa_otps (user_id);
