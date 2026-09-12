-- Part B (refresh-token-fix doc): lets a ClientApplication opt out of the
-- rotate-on-every-refresh behavior every client gets today, and run its
-- own refresh token TTL window, without touching the global default any
-- other tenant still gets. Both columns default to today's exact
-- behavior, so every existing row is completely unaffected by this
-- migration:
--   refresh_token_rotation_enabled = true  (same remove-and-remint path
--                                            UserLoginServiceImpl.refreshToken()
--                                            already uses)
--   refresh_token_ttl_days         = NULL  (falls back to the existing
--                                            global
--                                            app.authorization-server.refresh-token-ttl-days
--                                            property, unchanged)
ALTER TABLE client_applications
    ADD COLUMN refresh_token_rotation_enabled BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN refresh_token_ttl_days INTEGER;
