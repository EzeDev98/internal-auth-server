-- Step 11B: user_sessions.phone_number becomes optional, informational-only
-- data. Session lookups now key on user_id (see SessionManagementServiceImpl's
-- class Javadoc) - phone_number being NOT NULL silently broke session
-- tracking for any email-only user, since phone number has been optional
-- on users since Stage 2.

ALTER TABLE user_sessions ALTER COLUMN phone_number DROP NOT NULL;
