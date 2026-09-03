-- Step 13E: drop the deferred Keycloak fields.
--
-- Role.keycloakRoleId and PermissionGroup/SubPermissionGroup.keycloakGroupId
-- have been null on every row since Step 13C's control-flow rewrite (this
-- app no longer calls Keycloak to mirror RBAC objects), and KeycloakService/
-- KeycloakServiceImpl - the only thing that ever wrote to them - is deleted
-- in this same step. Nothing reads or writes these columns any more.

ALTER TABLE roles DROP COLUMN keycloak_role_id;
ALTER TABLE permission_groups DROP COLUMN keycloak_group_id;
ALTER TABLE sub_permission_group DROP COLUMN keycloak_group_id;
