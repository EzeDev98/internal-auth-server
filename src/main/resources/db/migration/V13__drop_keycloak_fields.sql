-- Drops the Keycloak id columns.
ALTER TABLE roles DROP COLUMN keycloak_role_id;
ALTER TABLE permission_groups DROP COLUMN keycloak_group_id;
ALTER TABLE sub_permission_group DROP COLUMN keycloak_group_id;
