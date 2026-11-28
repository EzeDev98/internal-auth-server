-- Scopes password reset OTPs to a client application.
TRUNCATE TABLE password_reset_otps;

ALTER TABLE password_reset_otps
    ADD COLUMN client_application_id BIGINT NOT NULL;
ALTER TABLE password_reset_otps
    ADD CONSTRAINT fk_password_reset_otps_client_application
        FOREIGN KEY (client_application_id) REFERENCES client_applications (id);
CREATE INDEX idx_password_reset_otps_client_application_id ON password_reset_otps (client_application_id);
