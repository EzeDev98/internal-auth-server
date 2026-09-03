package com.internal.auth.common.crypto;

import com.internal.auth.common.exception.InternalServerErrorException;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Stage 2 punch-list item 4 (credential storage policy): the single place
 * this app hashes a secret that must be looked up by exact-match equality,
 * rather than verified with a single-record matches() check.
 *
 * Deliberately NOT the same mechanism as password/OTP/client-secret hashing
 * (BCrypt, via the PasswordEncoder bean - see WebSecurityConfig,
 * PasswordResetServiceImpl, OtpService). BCrypt is intentionally slow and
 * salted per-hash, which makes it unsuitable for "find the one row whose
 * hash matches this value" queries - you cannot look up a BCrypt hash by
 * equality without already knowing which row to compare against, and
 * re-hashing every stored value on every request to check for a match does
 * not scale. What belongs here instead: values that are already
 * high-entropy and unpredictable on their own (a random reset token, a
 * signed bearer JWT) where the goal is only "do not store this
 * bearer-usable value in plaintext", not "resist brute force of a
 * low-entropy secret". SHA-256 is deterministic and fast, which is exactly
 * what a direct findByXHash lookup needs.
 *
 * Passwords, OTPs, and client secrets do NOT belong here - they go through
 * PasswordEncoder (BCrypt) instead, because those values either are or can
 * be low-entropy/human-chosen and need brute-force resistance, not just
 * lookup-by-hash.
 */
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
