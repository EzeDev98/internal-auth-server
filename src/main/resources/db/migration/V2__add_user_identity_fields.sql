-- Adds timestamps, the enabled flag and verification flags to users.
ALTER TABLE users
    ADD COLUMN updated_at          TIMESTAMP,
    ADD COLUMN password_changed_at TIMESTAMP,
    ADD COLUMN enabled             BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN email_verified      BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN phone_verified      BOOLEAN NOT NULL DEFAULT false;
