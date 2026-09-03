-- Stage 2 punch-list item 1: add the new User identity fields introduced
-- when the entity moved from feature.rbac.model to feature.identity.model.
--
-- enabled / email_verified / phone_verified are backfilled via DEFAULT so
-- any existing rows become "active, unverified" rather than violating the
-- new NOT NULL constraints. updated_at and password_changed_at are left
-- nullable - Hibernate's @UpdateTimestamp populates updated_at from the
-- next write onward, and password_changed_at has no meaningful backfill
-- value for rows whose password was set before this column existed.

ALTER TABLE users
    ADD COLUMN updated_at          TIMESTAMP,
    ADD COLUMN password_changed_at TIMESTAMP,
    ADD COLUMN enabled             BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN email_verified      BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN phone_verified      BOOLEAN NOT NULL DEFAULT false;
