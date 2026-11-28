-- Drops the scope columns from user permission groups.
ALTER TABLE user_permission_group
    DROP COLUMN scope_type,
    DROP COLUMN scope_value;
