package com.internal.auth.testsupport.builder;

import com.internal.auth.feature.signingkey.enums.SigningKeyStatus;
import com.internal.auth.feature.signingkey.model.SigningKey;

import java.time.LocalDateTime;
import java.util.concurrent.atomic.AtomicLong;

/**
 * encryptedPrivateKey must be real AES-256-GCM ciphertext produced by the
 * live SecretEncryptionService bean (using application-test.properties'
 * TEST-ONLY app.secret-encryption-key) - this plain builder can't produce
 * that itself since it isn't Spring-managed. Inject SecretEncryptionService
 * in the test and call
 * .withEncryptedPrivateKey(secretEncryptionService.encrypt(base64Pem))
 * before building. The default value below is a placeholder that will fail
 * to decrypt - fine for tests that only check row shape/status (Step 9),
 * not ones exercising SigningKeyServiceImpl's actual decrypt/JWKSet path
 * (Step 8B).
 */
public class SigningKeyTestDataBuilder {

    private static final AtomicLong COUNTER = new AtomicLong();

    private String kid;
    private String encryptedPrivateKey = "UNENCRYPTED-PLACEHOLDER-SET-VIA-withEncryptedPrivateKey";
    private boolean current = false;
    private SigningKeyStatus status = SigningKeyStatus.ACTIVE;
    private LocalDateTime retiredAt = null;

    private SigningKeyTestDataBuilder() {
        this.kid = "test-kid-" + COUNTER.incrementAndGet();
    }

    public static SigningKeyTestDataBuilder aSigningKey() {
        return new SigningKeyTestDataBuilder();
    }

    public SigningKeyTestDataBuilder withKid(String kid) {
        this.kid = kid;
        return this;
    }

    public SigningKeyTestDataBuilder withEncryptedPrivateKey(String encryptedPrivateKey) {
        this.encryptedPrivateKey = encryptedPrivateKey;
        return this;
    }

    public SigningKeyTestDataBuilder asCurrent() {
        this.current = true;
        return this;
    }

    public SigningKeyTestDataBuilder withStatus(SigningKeyStatus status) {
        this.status = status;
        return this;
    }

    public SigningKeyTestDataBuilder withRetiredAt(LocalDateTime retiredAt) {
        this.retiredAt = retiredAt;
        this.status = SigningKeyStatus.RETIRED;
        return this;
    }

    public SigningKey build() {
        SigningKey signingKey = new SigningKey();
        signingKey.setKid(kid);
        signingKey.setEncryptedPrivateKey(encryptedPrivateKey);
        signingKey.setCurrent(current);
        signingKey.setStatus(status);
        signingKey.setRetiredAt(retiredAt);
        return signingKey;
    }
}
