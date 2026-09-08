-- Step 2E (React Admin Client plan v4): the admin Sessions - List screen
-- needs to filter by device and IP, but user_sessions never captured
-- either - JwtSessionTrackingFilter only ever recorded userId, an
-- optional phoneNumber, and the token hash. Both columns are nullable:
-- every session row created before this migration has neither.

ALTER TABLE user_sessions ADD COLUMN ip_address VARCHAR(45);
ALTER TABLE user_sessions ADD COLUMN user_agent VARCHAR(500);
