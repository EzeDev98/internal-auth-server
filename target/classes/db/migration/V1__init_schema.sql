-- Baseline schema for internal-auth-server (Stage 1 punch-list item 4).
--
-- Targets PostgreSQL only - the app's production datastore. Local/dev runs
-- against MySQL with Hibernate's own ddl-auto=update and never runs Flyway
-- (see application-dev.properties / application-prod.properties), so this
-- file intentionally has no MySQL counterpart.
--
-- Column set, nullability and lengths are taken directly from the JPA
-- entities under com.internal.auth.feature.*.model so that
-- spring.jpa.hibernate.ddl-auto=validate (prod) passes against this schema
-- without Hibernate needing to alter anything at startup.

CREATE TABLE users (
    id           BIGSERIAL PRIMARY KEY,
    username     VARCHAR(255) NOT NULL,
    phone_number VARCHAR(255),
    email        VARCHAR(255),
    password     VARCHAR(255),
    created_at   TIMESTAMP,
    CONSTRAINT uk_users_username       UNIQUE (username),
    CONSTRAINT uk_users_phone_number   UNIQUE (phone_number),
    CONSTRAINT uk_users_email          UNIQUE (email),
    CONSTRAINT ck_users_phone_or_email CHECK (phone_number IS NOT NULL OR email IS NOT NULL)
);

CREATE TABLE roles (
    id               BIGSERIAL PRIMARY KEY,
    role_name        VARCHAR(255),
    description      VARCHAR(255),
    keycloak_role_id VARCHAR(255),
    created_at       TIMESTAMP
);

CREATE TABLE permission_groups (
    id                BIGSERIAL PRIMARY KEY,
    group_name        VARCHAR(255),
    description       VARCHAR(255),
    keycloak_group_id VARCHAR(255),
    created_at        TIMESTAMP
);

-- Renamed from the entity's former "sub-permission-group" @Table value.
-- A hyphenated identifier needs to be double-quoted on every single
-- reference or Postgres (and most tooling) folds/mangles it - a
-- portability trap with no upside. SubPermissionGroup.java's @Table
-- annotation is updated to match in this same patch.
CREATE TABLE sub_permission_group (
    id                BIGSERIAL PRIMARY KEY,
    group_name        VARCHAR(255),
    description       VARCHAR(255),
    parent_group_id   VARCHAR(255),
    keycloak_group_id VARCHAR(255),
    created_at        TIMESTAMP
);

CREATE TABLE role_permission_group_mapping (
    id                       BIGSERIAL PRIMARY KEY,
    role_id                  BIGINT,
    permission_group_id      BIGINT,
    sub_permission_group_id  BIGINT,
    created_at               TIMESTAMP,
    CONSTRAINT fk_rpgm_role
        FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE,
    CONSTRAINT fk_rpgm_permission_group
        FOREIGN KEY (permission_group_id) REFERENCES permission_groups (id) ON DELETE CASCADE,
    CONSTRAINT fk_rpgm_sub_permission_group
        FOREIGN KEY (sub_permission_group_id) REFERENCES sub_permission_group (id) ON DELETE CASCADE
);
CREATE INDEX idx_rpgm_role_id ON role_permission_group_mapping (role_id);
CREATE INDEX idx_rpgm_permission_group_id ON role_permission_group_mapping (permission_group_id);
CREATE INDEX idx_rpgm_sub_permission_group_id ON role_permission_group_mapping (sub_permission_group_id);

CREATE TABLE user_permission_group (
    id                       BIGSERIAL PRIMARY KEY,
    user_id                  BIGINT,
    permission_group_id      BIGINT,
    sub_permission_group_id  BIGINT,
    scope_type               VARCHAR(255),
    scope_value               VARCHAR(255),
    created_at               TIMESTAMP,
    CONSTRAINT fk_upg_user
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_upg_permission_group
        FOREIGN KEY (permission_group_id) REFERENCES permission_groups (id) ON DELETE CASCADE,
    CONSTRAINT fk_upg_sub_permission_group
        FOREIGN KEY (sub_permission_group_id) REFERENCES sub_permission_group (id) ON DELETE CASCADE
);
CREATE INDEX idx_upg_user_id ON user_permission_group (user_id);
CREATE INDEX idx_upg_permission_group_id ON user_permission_group (permission_group_id);
CREATE INDEX idx_upg_sub_permission_group_id ON user_permission_group (sub_permission_group_id);

CREATE TABLE user_roles (
    id         BIGSERIAL PRIMARY KEY,
    user_id    BIGINT,
    role_id    BIGINT,
    created_at TIMESTAMP,
    CONSTRAINT fk_ur_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_ur_role FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE
);
CREATE INDEX idx_ur_user_id ON user_roles (user_id);
CREATE INDEX idx_ur_role_id ON user_roles (role_id);

-- No live code references PermissionScopesRepository (repo-wide grep finds
-- zero callers beyond its own declaration) - this looks like dead/orphaned
-- design. Included anyway because the JPA entity + @Table mapping still
-- exist, and ddl-auto=validate will fail app startup if its table is
-- missing. Worth confirming and dropping (table, entity, repository
-- together) in a later cleanup pass - flagging here rather than deciding
-- unilaterally.
CREATE TABLE permission_scope (
    id          BIGSERIAL PRIMARY KEY,
    scope_type  VARCHAR(255),
    scope_value VARCHAR(255),
    created_at  TIMESTAMP
);

CREATE TABLE user_sessions (
    id           BIGSERIAL PRIMARY KEY,
    user_id      BIGINT NOT NULL,
    phone_number VARCHAR(255) NOT NULL,
    token        VARCHAR(2000) NOT NULL,
    is_active    BOOLEAN NOT NULL,
    created_at   TIMESTAMP,
    ended_at     TIMESTAMP,
    end_reason   VARCHAR(50),
    CONSTRAINT uk_user_sessions_token UNIQUE (token),
    CONSTRAINT fk_user_sessions_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);
CREATE INDEX idx_user_sessions_user_id ON user_sessions (user_id);

CREATE TABLE password_reset_otps (
    id             BIGSERIAL PRIMARY KEY,
    user_id        BIGINT NOT NULL,
    phone_number   VARCHAR(255) NOT NULL,
    otp_hash       VARCHAR(255) NOT NULL,
    expires_at     TIMESTAMP NOT NULL,
    attempt_count  INTEGER NOT NULL,
    max_attempts   INTEGER NOT NULL,
    status         VARCHAR(255) NOT NULL,
    created_at     TIMESTAMP,
    verified_at    TIMESTAMP,
    invalidated_at TIMESTAMP,
    last_sent_at   TIMESTAMP,
    CONSTRAINT fk_password_reset_otps_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);
CREATE INDEX idx_password_reset_otps_user_id ON password_reset_otps (user_id);

CREATE TABLE password_reset_tokens (
    id         BIGSERIAL PRIMARY KEY,
    user_id    BIGINT NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used       BOOLEAN NOT NULL,
    created_at TIMESTAMP,
    used_at    TIMESTAMP,
    CONSTRAINT uk_password_reset_tokens_token_hash UNIQUE (token_hash),
    CONSTRAINT fk_password_reset_tokens_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);
CREATE INDEX idx_password_reset_tokens_user_id ON password_reset_tokens (user_id);
