package com.internal.auth.common.util;

import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Unit tests for SecretEncryptionService. */
class SecretEncryptionServiceTest {
    private static final String VALID_KEY = "iak3c/+SZanL/YrmpeN6g+bPWpaiOWm6VMng3kZ9Jlk=";
    private static final String WRONG_LENGTH_KEY = "ZGWro0I8sOPD3kxGxzOjWQ==";

    @Test
    void encryptThenDecrypt_roundTripsToOriginalPlaintext() {
        SecretEncryptionService service = newInitializedService();
        String plaintext = "super-secret-private-key-pem-content";

        String encrypted = service.encrypt(plaintext);
        String decrypted = service.decrypt(encrypted);

        assertThat(decrypted).isEqualTo(plaintext);
        assertThat(encrypted).isNotEqualTo(plaintext);
    }

    @Test
    void encrypt_usesAFreshRandomIvEveryCall() {
        SecretEncryptionService service = newInitializedService();
        String plaintext = "same-plaintext-both-times";

        String first = service.encrypt(plaintext);
        String second = service.encrypt(plaintext);

        assertThat(first).isNotEqualTo(second);
        assertThat(service.decrypt(first)).isEqualTo(plaintext);
        assertThat(service.decrypt(second)).isEqualTo(plaintext);
    }

    @Test
    void decrypt_tamperedCiphertextFailsToDecrypt() {
        SecretEncryptionService service = newInitializedService();
        String encrypted = service.encrypt("do-not-let-this-be-readable-after-tampering");

        byte[] combined = Base64.getDecoder().decode(encrypted);
        combined[combined.length - 1] ^= 0x01;
        String tampered = Base64.getEncoder().encodeToString(combined);

        assertThatThrownBy(() -> service.decrypt(tampered))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Failed to decrypt");
    }

    @Test
    void init_withNullKey_failsBoot() {
        SecretEncryptionService service = new SecretEncryptionService();

        assertThatThrownBy(service::init)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("app.secret-encryption-key is required");
    }

    @Test
    void init_withBlankKey_failsBoot() {
        SecretEncryptionService service = new SecretEncryptionService();
        ReflectionTestUtils.setField(service, "base64Key", "   ");

        assertThatThrownBy(service::init)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("app.secret-encryption-key is required");
    }

    @Test
    void init_withInvalidBase64_failsBoot() {
        SecretEncryptionService service = new SecretEncryptionService();
        ReflectionTestUtils.setField(service, "base64Key", "not-valid-base64!!!");

        assertThatThrownBy(service::init)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not valid Base64");
    }

    @Test
    void init_withWrongDecodedLength_failsBoot() {
        SecretEncryptionService service = new SecretEncryptionService();
        ReflectionTestUtils.setField(service, "base64Key", WRONG_LENGTH_KEY);

        assertThatThrownBy(service::init)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("must decode to exactly 32 bytes");
    }

    private SecretEncryptionService newInitializedService() {
        SecretEncryptionService service = new SecretEncryptionService();
        ReflectionTestUtils.setField(service, "base64Key", VALID_KEY);
        service.init();
        return service;
    }
}
