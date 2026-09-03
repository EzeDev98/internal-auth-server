-- Step 13A: a genuinely fine-grained Permission entity (an action on a
-- resource, e.g. NOTE_CREATE, TRANSACTION_VIEW), distinct from
-- permission_groups - which, despite the name, groups USERS (a
-- team/org-unit concept), not actions. Schema only - not yet wired into
-- PermissionManagementServiceImpl, any controller, or the JWT roles claim;
-- that control-flow rewrite is Step 13C's job. See Permission.java's class
-- javadoc for the full rationale, including why permission_name is a
-- single flat identifier rather than separate resource/action columns.
CREATE TABLE permissions (
    id              BIGSERIAL PRIMARY KEY,
    permission_name VARCHAR(255),
    description     VARCHAR(255),
    created_at      TIMESTAMP
);

-- Mirrors role_permission_group_mapping's shape (which links roles to
-- permission_groups/sub_permission_group instead) - see
-- RolePermissionMapping.java's class javadoc.
CREATE TABLE role_permission_mapping (
    id            BIGSERIAL PRIMARY KEY,
    role_id       BIGINT,
    permission_id BIGINT,
    created_at    TIMESTAMP,
    CONSTRAINT fk_role_permission_mapping_role
        FOREIGN KEY (role_id) REFERENCES roles (id),
    CONSTRAINT fk_role_permission_mapping_permission
        FOREIGN KEY (permission_id) REFERENCES permissions (id)
);
CREATE INDEX idx_role_permission_mapping_role_id ON role_permission_mapping (role_id);
CREATE INDEX idx_role_permission_mapping_permission_id ON role_permission_mapping (permission_id);
