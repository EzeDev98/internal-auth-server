-- Multi-tenant user namespace (schema/model step only - registration/login
-- are not yet wired to use this; that's the next step).
--
-- Product decision: each integrating app (SyncPoint, Notare, future apps)
-- gets its own isolated user namespace, not one shared SSO-style identity -
-- two accounts may share a username/phone/email as long as they belong to
-- different client_applications rows. ClientApplication already exists and
-- is populated via Step 10D's admin endpoint
-- (POST ${app.title}/client-applications).
--
-- No existing user data is preserved (confirmed acceptable - still
-- pre-production). TRUNCATE ... CASCADE also clears every table with a FK
-- back to users (user_sessions, password_reset_otps, password_reset_tokens,
-- email_verification_tokens, login_mfa_otps, user_roles,
-- user_permission_group) so nothing is left pointing at a user_id that no
-- longer exists.
TRUNCATE TABLE users CASCADE;

ALTER TABLE users
    ADD COLUMN client_application_id BIGINT NOT NULL;

-- Deliberately NOT ON DELETE CASCADE, unlike the *_user FKs above. Those
-- cascade because deleting a user should take its own session/OTP/role
-- rows with it. This FK points the other way - deleting a
-- client_application should not silently mass-delete every user
-- registered under it. Left at the Postgres default (NO ACTION); revisit
-- once client-application deletion is actually built, if that's not the
-- behavior you want.
ALTER TABLE users
    ADD CONSTRAINT fk_users_client_application
        FOREIGN KEY (client_application_id) REFERENCES client_applications (id);

CREATE INDEX idx_users_client_application_id ON users (client_application_id);

-- Replace global uniqueness with per-app uniqueness. Postgres treats each
-- NULL as distinct in a UNIQUE constraint (no NULLS NOT DISTINCT here), so
-- multiple NULL phone_number/email rows per client_application_id remain
-- allowed - same behavior as today's global constraints, just scoped.
ALTER TABLE users DROP CONSTRAINT uk_users_username;
ALTER TABLE users DROP CONSTRAINT uk_users_phone_number;
ALTER TABLE users DROP CONSTRAINT uk_users_email;

ALTER TABLE users ADD CONSTRAINT uk_users_client_username     UNIQUE (client_application_id, username);
ALTER TABLE users ADD CONSTRAINT uk_users_client_phone_number UNIQUE (client_application_id, phone_number);
ALTER TABLE users ADD CONSTRAINT uk_users_client_email        UNIQUE (client_application_id, email);
