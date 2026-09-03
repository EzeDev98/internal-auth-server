-- Multi-tenant user namespace, OTP/token flows step - schema part only.
--
-- password_reset_otps and login_mfa_otps are both looked up by phone
-- number alone (findTopByPhoneNumberAndStatusOrderByCreatedAtDesc) - now
-- that the same phone number can belong to accounts in two different
-- client applications (see V8), that lookup is ambiguous: whichever OTP
-- was created most recently wins, regardless of which app's user is
-- verifying. This adds client_application_id so it can be scoped the same
-- way users.client_application_id scopes user lookups.
--
-- password_reset_tokens and email_verification_tokens are NOT touched
-- here - both are looked up by their own token_hash, which is already
-- unambiguous (a random 256-bit value, not a phone/email), so they need
-- no schema change.
--
-- No existing OTP data is preserved - same "pre-production, fine to wipe"
-- basis as V8. Plain TRUNCATE (no CASCADE) since nothing has a FK back to
-- either of these tables.
TRUNCATE TABLE password_reset_otps;
TRUNCATE TABLE login_mfa_otps;

ALTER TABLE password_reset_otps
    ADD COLUMN client_application_id BIGINT NOT NULL;
ALTER TABLE password_reset_otps
    ADD CONSTRAINT fk_password_reset_otps_client_application
        FOREIGN KEY (client_application_id) REFERENCES client_applications (id);
CREATE INDEX idx_password_reset_otps_client_application_id ON password_reset_otps (client_application_id);

ALTER TABLE login_mfa_otps
    ADD COLUMN client_application_id BIGINT NOT NULL;
ALTER TABLE login_mfa_otps
    ADD CONSTRAINT fk_login_mfa_otps_client_application
        FOREIGN KEY (client_application_id) REFERENCES client_applications (id);
CREATE INDEX idx_login_mfa_otps_client_application_id ON login_mfa_otps (client_application_id);
