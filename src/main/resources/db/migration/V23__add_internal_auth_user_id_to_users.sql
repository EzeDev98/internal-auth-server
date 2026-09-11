-- User.internalAuthUserId (see UserRegistrationServiceImpl,
-- AdminRegistrationServiceImpl, AdminUserServiceImpl - all generate it as
-- "IA_" + UUID.randomUUID()) was added to the entity without a matching
-- migration, so Hibernate's ddl-auto=validate correctly refused to boot
-- against a users table missing this column.
--
-- Table is still empty in every real environment (pre-production), so
-- NOT NULL can be added directly with no backfill step.
--
-- UNIQUE added here to actually enforce the invariant
-- UserRepository.findByInternalAuthUserId's own comment already assumes
-- ("internalAuthUserId is globally unique... never reused") - that finder
-- was relying on application-level UUID generation alone until now.
ALTER TABLE users
    ADD COLUMN internal_auth_user_id VARCHAR(255) NOT NULL;

ALTER TABLE users
    ADD CONSTRAINT uk_users_internal_auth_user_id UNIQUE (internal_auth_user_id);
