-- Allows password reset OTPs to be sent by email.
ALTER TABLE password_reset_otps ALTER COLUMN phone_number DROP NOT NULL;
ALTER TABLE password_reset_otps ADD COLUMN email VARCHAR(255);
CREATE INDEX idx_password_reset_otps_email ON password_reset_otps (email);
