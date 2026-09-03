-- Step 13B: application/client scoping for Role and PermissionGroup.
--
-- Today every Role and PermissionGroup is global - visible/assignable
-- regardless of which client application a user belongs to. This adds an
-- optional link to Step 8's ClientApplication so a Role/PermissionGroup
-- can instead be scoped to a single client.
--
-- Nullable by design (unlike V9's OTP scoping, which was made mandatory
-- once users were split by client): client_application_id = NULL means
-- "global" and continues to mean exactly what every existing row already
-- means, so no data loss/truncate is needed here - existing rows simply
-- become explicitly global rather than implicitly global.
--
-- SubPermissionGroup is deliberately not touched - the roadmap step only
-- calls out Role/PermissionGroup.
--
-- No repository/service/controller enforcement is added here - this is
-- the data model only, mirroring Step 13A's Permission entity. Actually
-- filtering role/group assignment or permission checks by client is
-- deferred until something needs it.

ALTER TABLE roles
    ADD COLUMN client_application_id BIGINT NULL;

ALTER TABLE roles
    ADD CONSTRAINT fk_roles_client_application
        FOREIGN KEY (client_application_id) REFERENCES client_applications (id);

CREATE INDEX idx_roles_client_application_id ON roles (client_application_id);

ALTER TABLE permission_groups
    ADD COLUMN client_application_id BIGINT NULL;

ALTER TABLE permission_groups
    ADD CONSTRAINT fk_permission_groups_client_application
        FOREIGN KEY (client_application_id) REFERENCES client_applications (id);

CREATE INDEX idx_permission_groups_client_application_id ON permission_groups (client_application_id);
