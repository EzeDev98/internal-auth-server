-- Adds the internal auth user id to users.
ALTER TABLE users
    ADD COLUMN internal_auth_user_id VARCHAR(255) NOT NULL;

ALTER TABLE users
    ADD CONSTRAINT uk_users_internal_auth_user_id UNIQUE (internal_auth_user_id);
