-- Absolute cap on how long a persistent (non-rotating) refresh token session
-- can live, counted from the original login no matter how often it is used
-- (Keycloak's "Offline Session Max"). NULL = no cap, which is today's exact
-- behavior, so every existing client is unaffected by this migration.
-- Only meaningful when refresh_token_rotation_enabled = false (V25).
ALTER TABLE client_applications ADD COLUMN refresh_token_max_lifetime_days INTEGER;
