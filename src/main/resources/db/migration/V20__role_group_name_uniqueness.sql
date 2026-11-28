-- Makes role, permission group and sub-group names unique.
ALTER TABLE roles
    ADD CONSTRAINT uk_roles_role_name UNIQUE (role_name);

ALTER TABLE permission_groups
    ADD CONSTRAINT uk_permission_groups_group_name UNIQUE (group_name);

ALTER TABLE sub_permission_group
    ADD CONSTRAINT uk_sub_permission_group_group_name UNIQUE (group_name);
