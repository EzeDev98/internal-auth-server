-- Adds the audit log and event publication tables.
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
