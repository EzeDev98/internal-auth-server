-- Fixes a check-then-act race in PermissionEntityServiceImpl: createRole/
-- createSuperGroup/createSubGroup each run an isRoleExist/isGroupExist/
-- isSubGroupExist lookup before saving, with no DB-level constraint behind
-- it. Two concurrent calls (e.g. two registrations racing
-- UserServiceImpl.addUserToDefaultPermissionGroup's get-or-create of the
-- shared "basic_access" role / "default-group" group) can both pass the
-- check and both insert, leaving duplicate rows with the same name - a
-- later findByRoleName/findByGroupName lookup against those duplicates
-- then throws IncorrectResultSizeDataAccessException instead of failing
-- cleanly at creation time. Same class of gap Step 10B closed for User by
-- backstopping its own check-then-act uniqueness checks with a DB
-- constraint.
--
-- Pre-production, same basis as V8/V9/V12: no existing data to conflict
-- with, so a plain ADD CONSTRAINT is safe here without a dedupe step.

ALTER TABLE roles
    ADD CONSTRAINT uk_roles_role_name UNIQUE (role_name);

ALTER TABLE permission_groups
    ADD CONSTRAINT uk_permission_groups_group_name UNIQUE (group_name);

ALTER TABLE sub_permission_group
    ADD CONSTRAINT uk_sub_permission_group_group_name UNIQUE (group_name);
