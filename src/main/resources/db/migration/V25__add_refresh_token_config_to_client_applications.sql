-- Adds refresh token rotation and lifetime settings to client applications.
ALTER TABLE client_applications
    ADD COLUMN refresh_token_rotation_enabled BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN refresh_token_ttl_days INTEGER;
