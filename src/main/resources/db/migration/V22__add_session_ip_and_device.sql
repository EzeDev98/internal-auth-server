-- Adds the IP address and user agent to sessions.
ALTER TABLE user_sessions ADD COLUMN ip_address VARCHAR(45);
ALTER TABLE user_sessions ADD COLUMN user_agent VARCHAR(500);
