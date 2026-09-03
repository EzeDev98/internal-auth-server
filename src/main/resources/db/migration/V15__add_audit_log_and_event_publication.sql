-- Step 14A: audit_log (the audit trail's storage) and event_publication
-- (Spring Modulith's own durable event-publication registry, which backs
-- the audit-event flow - see AuditEventListener's Javadoc). Prod runs
-- Flyway, so both tables are created here rather than through Modulith's
-- auto-schema-init, which is explicitly disabled for prod (see
-- spring.modulith.events.jdbc.schema-initialization.enabled=false in
-- application-prod.properties). Dev keeps relying on that auto-init
-- instead (see application-dev.properties), consistent with dev never
-- running Flyway migrations at all.

CREATE TABLE audit_log (
    id                      BIGSERIAL PRIMARY KEY,
    actor_user_id           BIGINT,
    actor_username          VARCHAR(255),
    client_application_id   BIGINT,
    action                  VARCHAR(100) NOT NULL,
    description             VARCHAR(1000),
    created_at              TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_log_actor_user_id ON audit_log (actor_user_id);
CREATE INDEX idx_audit_log_client_application_id ON audit_log (client_application_id);
CREATE INDEX idx_audit_log_created_at ON audit_log (created_at);

-- Spring Modulith's own table, exact DDL per the official PostgreSQL
-- schema reference (docs.spring.io/spring-modulith/reference/appendix.html#schemas).
CREATE TABLE IF NOT EXISTS event_publication
(
    id                     UUID NOT NULL,
    listener_id            TEXT NOT NULL,
    event_type             TEXT NOT NULL,
    serialized_event       TEXT NOT NULL,
    publication_date       TIMESTAMP WITH TIME ZONE NOT NULL,
    completion_date        TIMESTAMP WITH TIME ZONE,
    status                 TEXT,
    completion_attempts    INT,
    last_resubmission_date TIMESTAMP WITH TIME ZONE,
    PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS event_publication_serialized_event_hash_idx ON event_publication USING hash (serialized_event);
CREATE INDEX IF NOT EXISTS event_publication_by_completion_date_idx ON event_publication (completion_date);
