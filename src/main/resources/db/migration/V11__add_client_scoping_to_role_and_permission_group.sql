-- Adds client application scoping to roles and permission groups.
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
