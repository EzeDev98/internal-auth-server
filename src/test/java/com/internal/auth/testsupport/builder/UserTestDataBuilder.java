package com.internal.auth.testsupport.builder;

import com.internal.auth.feature.identity.model.User;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Fluent test-data builder for User. Entities in this codebase use plain
 * Lombok @Getter/@Setter (no @Builder), so this is hand-written rather than
 * generated - see IntegrationTestBase for the shared Postgres a built User
 * gets persisted into (via UserRepository, not this class).
 *
 * Defaults produce a valid, enabled, phone-verified local account scoped to
 * clientApplicationId=1L - override whatever a specific test cares about.
 * username/phoneNumber/email are unique only per client_application_id (see
 * User's class javadoc / the V8 migration), so the defaults include a
 * per-JVM-run counter to avoid collisions between tests that don't
 * override them.
 *
 * The default password hash is a real, valid-format BCrypt hash of the
 * literal string "not-a-real-password" - safe to embed (it protects
 * nothing), and valid enough that PasswordEncoder#matches(...) against it
 * returns false cleanly instead of throwing on a malformed hash. Tests that
 * need a specific known password to actually authenticate with must inject
 * the real PasswordEncoder bean and call withPasswordHash(encoder.encode(...)).
 */
public class UserTestDataBuilder {

    private static final AtomicLong COUNTER = new AtomicLong();
    private static final String PLACEHOLDER_BCRYPT_HASH =
            "$2b$10$KT9XJ9oExA1U5Ju045zcFeN2E/JfLEdyLyRBSwD9gob3vFkLccOPi";

    private Long clientApplicationId = 1L;
    private String username;
    private String phoneNumber;
    private String email = null;
    private String password = PLACEHOLDER_BCRYPT_HASH;
    private boolean enabled = true;
    private boolean emailVerified = false;
    private boolean phoneVerified = true;
    private boolean mfaEnabled = false;

    private UserTestDataBuilder() {
        long n = COUNTER.incrementAndGet();
        this.username = "test_user_" + n;
        this.phoneNumber = "0801" + String.format("%07d", n % 10_000_000L);
    }

    public static UserTestDataBuilder aUser() {
        return new UserTestDataBuilder();
    }

    public UserTestDataBuilder withClientApplicationId(Long clientApplicationId) {
        this.clientApplicationId = clientApplicationId;
        return this;
    }

    public UserTestDataBuilder withUsername(String username) {
        this.username = username;
        return this;
    }

    public UserTestDataBuilder withPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
        return this;
    }

    public UserTestDataBuilder withEmail(String email) {
        this.email = email;
        return this;
    }

    /** Pass an already-BCrypt-hashed value - this builder never hashes for you. */
    public UserTestDataBuilder withPasswordHash(String bcryptHash) {
        this.password = bcryptHash;
        return this;
    }

    public UserTestDataBuilder withEnabled(boolean enabled) {
        this.enabled = enabled;
        return this;
    }

    public UserTestDataBuilder withEmailVerified(boolean verified) {
        this.emailVerified = verified;
        return this;
    }

    public UserTestDataBuilder withPhoneVerified(boolean verified) {
        this.phoneVerified = verified;
        return this;
    }

    public UserTestDataBuilder withMfaEnabled(boolean enabled) {
        this.mfaEnabled = enabled;
        return this;
    }

    public User build() {
        User user = new User();
        user.setClientApplicationId(clientApplicationId);
        user.setUsername(username);
        user.setPhoneNumber(phoneNumber);
        user.setEmail(email);
        user.setPassword(password);
        user.setEnabled(enabled);
        user.setEmailVerified(emailVerified);
        user.setPhoneVerified(phoneVerified);
        user.setMfaEnabled(mfaEnabled);
        return user;
    }
}
