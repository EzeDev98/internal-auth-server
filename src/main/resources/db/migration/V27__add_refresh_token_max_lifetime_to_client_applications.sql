-- Adds the refresh token maximum lifetime to client applications.
ALTER TABLE client_applications ADD COLUMN refresh_token_max_lifetime_days INTEGER;
