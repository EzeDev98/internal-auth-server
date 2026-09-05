-- Step 3 (durable OAuth2AuthorizationService): replaces
-- AuthorizationServerConfig's previous InMemoryOAuth2AuthorizationService
-- (every minted token's authorization record lived only in that one JVM's
-- heap - wiped on restart, not shared across instances/behind a load
-- balancer) with JdbcOAuth2AuthorizationService. Column set matches Spring
-- Security's own reference schema exactly
-- (org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql),
-- translated to PostgreSQL types (BYTEA instead of BLOB). No FK on
-- registered_client_id on purpose, matching the library's own schema -
-- RegisteredClientRepository is a separate abstraction (here,
-- ClientApplicationRegisteredClientRepository over client_applications) that
-- this table deliberately doesn't assume anything about beyond the id
-- string it stores.
--
-- Dev gets the equivalent table applied via spring.sql.init.* instead (see
-- application-dev.properties) - Flyway doesn't run there.
CREATE TABLE oauth2_authorization (
    id                             VARCHAR(100) NOT NULL,
    registered_client_id           VARCHAR(100) NOT NULL,
    principal_name                 VARCHAR(200) NOT NULL,
    authorization_grant_type       VARCHAR(100) NOT NULL,
    authorized_scopes              VARCHAR(1000) DEFAULT NULL,
    attributes                     BYTEA DEFAULT NULL,
    state                          VARCHAR(500) DEFAULT NULL,
    authorization_code_value       BYTEA DEFAULT NULL,
    authorization_code_issued_at   TIMESTAMP DEFAULT NULL,
    authorization_code_expires_at  TIMESTAMP DEFAULT NULL,
    authorization_code_metadata    BYTEA DEFAULT NULL,
    access_token_value             BYTEA DEFAULT NULL,
    access_token_issued_at         TIMESTAMP DEFAULT NULL,
    access_token_expires_at        TIMESTAMP DEFAULT NULL,
    access_token_metadata          BYTEA DEFAULT NULL,
    access_token_type              VARCHAR(100) DEFAULT NULL,
    access_token_scopes            VARCHAR(1000) DEFAULT NULL,
    oidc_id_token_value            BYTEA DEFAULT NULL,
    oidc_id_token_issued_at        TIMESTAMP DEFAULT NULL,
    oidc_id_token_expires_at       TIMESTAMP DEFAULT NULL,
    oidc_id_token_metadata         BYTEA DEFAULT NULL,
    refresh_token_value            BYTEA DEFAULT NULL,
    refresh_token_issued_at        TIMESTAMP DEFAULT NULL,
    refresh_token_expires_at       TIMESTAMP DEFAULT NULL,
    refresh_token_metadata         BYTEA DEFAULT NULL,
    user_code_value                BYTEA DEFAULT NULL,
    user_code_issued_at            TIMESTAMP DEFAULT NULL,
    user_code_expires_at           TIMESTAMP DEFAULT NULL,
    user_code_metadata             BYTEA DEFAULT NULL,
    device_code_value              BYTEA DEFAULT NULL,
    device_code_issued_at          TIMESTAMP DEFAULT NULL,
    device_code_expires_at         TIMESTAMP DEFAULT NULL,
    device_code_metadata           BYTEA DEFAULT NULL,
    PRIMARY KEY (id)
);
