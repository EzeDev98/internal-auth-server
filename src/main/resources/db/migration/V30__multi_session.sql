-- Step 17h (B-14): several signed-in devices per user, per client application.
--   max_active_sessions  how many sessions one user may hold in this app. 1 keeps today's
--                        behaviour exactly, so apps that rely on one session are untouched.
--   device_label         "Mac, Chrome", parsed from the User-Agent when the session is created.
--   last_active_at       touched when the session's token is refreshed (throttled).
--   authorization_id     the oauth2_authorization row (refresh token) this session was issued
--                        with, so one device can be signed out without touching the others.
ALTER TABLE client_applications ADD COLUMN max_active_sessions INTEGER NOT NULL DEFAULT 1;

ALTER TABLE user_sessions ADD COLUMN device_label     VARCHAR(100);
ALTER TABLE user_sessions ADD COLUMN last_active_at   TIMESTAMP;
ALTER TABLE user_sessions ADD COLUMN authorization_id VARCHAR(100);

CREATE INDEX idx_user_sessions_authorization_id ON user_sessions (authorization_id);
