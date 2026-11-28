-- Adds the phone verification OTP table.
CREATE TABLE phone_verification_otps (
    id                     BIGSERIAL PRIMARY KEY,
    user_id                BIGINT NOT NULL,
    client_application_id  BIGINT NOT NULL,
    phone_number           VARCHAR(255) NOT NULL,
    otp_hash               VARCHAR(255) NOT NULL,
    expires_at             TIMESTAMP NOT NULL,
    attempt_count          INTEGER NOT NULL,
    max_attempts           INTEGER NOT NULL,
    status                 VARCHAR(255) NOT NULL,
    created_at             TIMESTAMP,
    verified_at            TIMESTAMP,
    invalidated_at         TIMESTAMP,
    last_sent_at           TIMESTAMP,
    CONSTRAINT fk_phone_verification_otps_user
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_phone_verification_otps_client_application
        FOREIGN KEY (client_application_id) REFERENCES client_applications (id)
);
CREATE INDEX idx_phone_verification_otps_user_id ON phone_verification_otps (user_id);
CREATE INDEX idx_phone_verification_otps_client_application_id ON phone_verification_otps (client_application_id);
