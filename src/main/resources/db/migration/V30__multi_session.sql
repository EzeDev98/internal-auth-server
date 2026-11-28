-- Supports several active sessions per user per client application.
ALTER TABLE client_applications ADD COLUMN max_active_sessions INTEGER NOT NULL DEFAULT 1;

ALTER TABLE user_sessions ADD COLUMN device_label     VARCHAR(100);
ALTER TABLE user_sessions ADD COLUMN last_active_at   TIMESTAMP;
ALTER TABLE user_sessions ADD COLUMN authorization_id VARCHAR(100);

CREATE INDEX idx_user_sessions_authorization_id ON user_sessions (authorization_id);
