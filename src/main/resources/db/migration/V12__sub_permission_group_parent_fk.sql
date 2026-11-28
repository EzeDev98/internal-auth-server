-- Links each sub-group to its parent permission group with a foreign key.
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
