-- Scopes users to a client application, with username, phone number and email unique per application.
TRUNCATE TABLE users CASCADE;

ALTER TABLE users
    ADD COLUMN client_application_id BIGINT NOT NULL;

ALTER TABLE users
    ADD CONSTRAINT fk_users_client_application
        FOREIGN KEY (client_application_id) REFERENCES client_applications (id);

CREATE INDEX idx_users_client_application_id ON users (client_application_id);

ALTER TABLE users DROP CONSTRAINT uk_users_username;
ALTER TABLE users DROP CONSTRAINT uk_users_phone_number;
ALTER TABLE users DROP CONSTRAINT uk_users_email;

ALTER TABLE users ADD CONSTRAINT uk_users_client_username     UNIQUE (client_application_id, username);
ALTER TABLE users ADD CONSTRAINT uk_users_client_phone_number UNIQUE (client_application_id, phone_number);
ALTER TABLE users ADD CONSTRAINT uk_users_client_email        UNIQUE (client_application_id, email);
