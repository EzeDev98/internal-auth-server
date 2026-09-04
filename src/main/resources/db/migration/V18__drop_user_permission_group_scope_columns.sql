-- Drop UserPermissionGroup.scopeType/scopeValue: same dead-column pattern as
-- PermissionScope (V14). Zero getters/setters called anywhere in the codebase,
-- and no real users/data exist yet in this environment, so this is a clean drop
-- with nothing to migrate.

ALTER TABLE user_permission_group
    DROP COLUMN scope_type,
    DROP COLUMN scope_value;
