-- Makes the session phone number optional.
ALTER TABLE user_sessions ALTER COLUMN phone_number DROP NOT NULL;
