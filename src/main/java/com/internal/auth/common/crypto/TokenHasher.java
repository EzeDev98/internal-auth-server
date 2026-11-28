package com.internal.auth.common.crypto;

import com.internal.auth.common.exception.InternalServerErrorException;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** Hashes secrets that must be looked up by exact match, such as session and refresh tokens. */
@Component
public class TokenHasher {

    public String sha256Hex(String raw) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(raw.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (byte b : hashBytes) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new InternalServerErrorException("Failed to hash value", e);
        }
    }
}
