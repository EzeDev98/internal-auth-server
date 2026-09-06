-- Step 13D: SubPermissionGroup.parentGroupId becomes a real FK.
--
-- Today parent_group_id is a bare VARCHAR that's supposed to match the
-- parent PermissionGroup's keycloak_group_id - but every PermissionGroup
-- has been created with keycloak_group_id = NULL since Step 13C's
-- control-flow rewrite stopped calling Keycloak at all, so that match has
-- been silently broken for every subgroup created under current code
-- (EntityUtilityService.getSubGroup/fetchAllUserPermissionGroups both
-- defensively threw "Parent group has no Keycloak ID assigned" rather
-- than NPE, but the parent/child relationship could never actually be
-- verified). This replaces it with a real FK to permission_groups(id).
--
-- No existing parent_group_id string value is a valid FK target, so - same
-- "pre-production, fine to wipe" basis as V8/V9 - this clears out
-- sub_permission_group and anything that references a subgroup, rather
-- than attempting a cast. Only rows scoped to a subgroup are touched:
-- role_permission_group_mapping/user_permission_group rows that instead
-- point directly at a PermissionGroup (sub_permission_group_id IS NULL)
-- are left alone.

DELETE FROM role_permission_group_mapping WHERE sub_permission_group_id IS NOT NULL;
DELETE FROM user_permission_group WHERE sub_permission_group_id IS NOT NULL;
DELETE FROM sub_permission_group;

ALTER TABLE sub_permission_group
    DROP COLUMN parent_group_id;

ALTER TABLE sub_permission_group
    ADD COLUMN parent_group_id BIGINT NOT NULL;

ALTER TABLE sub_permission_group
    ADD CONSTRAINT fk_sub_permission_group_parent_group
        FOREIGN KEY (parent_group_id) REFERENCES permission_groups (id);

CREATE INDEX idx_sub_permission_group_parent_group_id ON sub_permission_group (parent_group_id);
