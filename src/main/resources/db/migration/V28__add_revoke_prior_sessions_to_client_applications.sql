ALTER TABLE client_applications
    ADD COLUMN revoke_prior_sessions_on_login BOOLEAN NOT NULL DEFAULT TRUE;
