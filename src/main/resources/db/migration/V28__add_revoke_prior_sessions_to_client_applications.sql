-- Adds the revoke prior sessions on login setting to client applications.
ALTER TABLE client_applications
    ADD COLUMN revoke_prior_sessions_on_login BOOLEAN NOT NULL DEFAULT TRUE;
