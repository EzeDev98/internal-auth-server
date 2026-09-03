package com.internal.auth.common.util;

import com.internal.auth.common.constant.AppConstant;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;

/**
 * Step 14E. AES-256-GCM at-rest encryption for sensitive material stored in
 * the database - today that's only signing_key.encrypted_private_key (see
 * SigningKeyServiceImpl), but this is deliberately generic rather than
 * baked into that one class, so any future secret-shaped column can reuse
 * it.
 *
 * app.secret-encryption-key (SECRET_ENCRYPTION_KEY) has NO insecure
 * ephemeral fallback, unlike the signing key itself
 * (SigningKeyServiceImpl#bootstrapIfEmpty) - that fallback is acceptable
 * there because losing that key only invalidates outstanding tokens.
 * Losing or rotating THIS key would silently orphan every row it already
 * encrypted (permanently undecryptable), which is a strictly worse failure
 * mode - so this fails fast at boot instead, same fail-closed pattern
 * application-prod.properties already uses for datasource credentials.
 *
 * Storage format: Base64(12-byte random IV || GCM ciphertext+tag). A fresh
 * random IV per call, never reused - required for GCM's security
 * guarantees.
 */
@Service
public class SecretEncryptionService {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH_BYTES = 12;
    private static final int GCM_TAG_LENGTH_BITS = 128;

    @Value("${app.secret-encryption-key}")
    private String base64Key;

    private SecretKeySpec keySpec;

    @PostConstruct
    public void init() {
        if (base64Key == null || base64Key.isBlank()) {
            throw new IllegalStateException(
                    "app.secret-encryption-key is required - generate one with `openssl rand -base64 32` and set "
                            + "SECRET_ENCRYPTION_KEY (or add it to application-local.properties for local dev, same "
                            + "as the signing key). There is deliberately no insecure fallback for this one - see "
                            + "this class's javadoc for why.");
        }
        byte[] keyBytes;
        try {
            keyBytes = Base64.getDecoder().decode(base64Key);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("app.secret-encryption-key is not valid Base64", e);
        }
        if (keyBytes.length != 32) {
            throw new IllegalStateException(
                    "app.secret-encryption-key must decode to exactly 32 bytes (AES-256) - got " + keyBytes.length);
        }
        this.keySpec = new SecretKeySpec(keyBytes, "AES");
    }

    public String encrypt(String plaintext) {
        try {
            byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
            AppConstant.SECURE_RANDOM.nextBytes(iv);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            byte[] combined = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);
            return Base64.getEncoder().encodeToString(combined);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to encrypt secret", e);
        }
    }

    public String decrypt(String encoded) {
        try {
            byte[] combined = Base64.getDecoder().decode(encoded);
            byte[] iv = Arrays.copyOfRange(combined, 0, GCM_IV_LENGTH_BYTES);
            byte[] ciphertext = Arrays.copyOfRange(combined, GCM_IV_LENGTH_BYTES, combined.length);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
            byte[] plaintext = cipher.doFinal(ciphertext);
            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(
                    "Failed to decrypt secret - wrong app.secret-encryption-key, or the stored value predates "
                            + "this encryption scheme", e);
        }
    }
}
