package com.internal.auth.testsupport.builder;

import com.internal.auth.feature.identity.model.User;

import java.util.concurrent.atomic.AtomicLong;

/** Test data builder for User. */
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
        return user;
    }
}
