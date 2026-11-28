-- Adds fine-grained permissions and role to permission mappings.
CREATE TABLE permissions (
    id              BIGSERIAL PRIMARY KEY,
    permission_name VARCHAR(255),
    description     VARCHAR(255),
    created_at      TIMESTAMP
);

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
