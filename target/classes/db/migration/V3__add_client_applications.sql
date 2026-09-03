-- Stage 2 punch-list item 3: client application data model (the "who is
-- calling this service" counterpart to the users table). This is schema
-- only - nothing in the application code creates, reads, or wires these
-- rows into Spring Authorization Server's RegisteredClientRepository yet;
-- that integration is out of scope until Stage 4 per the architecture
-- assessment. client_secret is nullable to allow public (PKCE-only)
-- clients with no secret at all - see ClientApplication.java for the full
-- rationale.

CREATE TABLE client_applications (
    id            BIGSERIAL PRIMARY KEY,
    client_id     VARCHAR(255) NOT NULL,
    client_secret VARCHAR(255),
    name          VARCHAR(255) NOT NULL,
    description   VARCHAR(1000),
    enabled       BOOLEAN NOT NULL DEFAULT true,
    created_at    TIMESTAMP,
    updated_at    TIMESTAMP,
    CONSTRAINT uk_client_applications_client_id UNIQUE (client_id)
);

CREATE TABLE client_application_redirect_uris (
    client_application_id BIGINT NOT NULL,
    redirect_uri           VARCHAR(2000) NOT NULL,
    CONSTRAINT fk_car_client_application
        FOREIGN KEY (client_application_id) REFERENCES client_applications (id) ON DELETE CASCADE
);
CREATE INDEX idx_car_client_application_id ON client_application_redirect_uris (client_application_id);

CREATE TABLE client_application_scopes (
    client_application_id BIGINT NOT NULL,
    scope                  VARCHAR(255) NOT NULL,
    CONSTRAINT fk_cas_client_application
        FOREIGN KEY (client_application_id) REFERENCES client_applications (id) ON DELETE CASCADE
);
CREATE INDEX idx_cas_client_application_id ON client_application_scopes (client_application_id);

CREATE TABLE client_application_grant_types (
    client_application_id BIGINT NOT NULL,
    grant_type             VARCHAR(255) NOT NULL,
    CONSTRAINT fk_cagt_client_application
        FOREIGN KEY (client_application_id) REFERENCES client_applications (id) ON DELETE CASCADE
);
CREATE INDEX idx_cagt_client_application_id ON client_application_grant_types (client_application_id);
