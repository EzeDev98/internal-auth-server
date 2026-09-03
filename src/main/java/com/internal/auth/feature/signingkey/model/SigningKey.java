package com.internal.auth.feature.signingkey.model;

import com.internal.auth.feature.signingkey.enums.SigningKeyStatus;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

/**
 * Step 14D. One row per RSA signing key this server has ever minted tokens
 * with. Exactly one row has current = true at a time (enforced by a
 * partial unique index in V16 - see that migration) - that's the key new
 * tokens are signed with. Every ACTIVE row (current or not) stays in the
 * JWKSource so tokens signed by a just-superseded key still verify during
 * the grace period (see SigningKeyServiceImpl#rotate). A row moves to
 * RETIRED (and drops out of the JWKSet entirely) once it's older than
 * AppConstant.SIGNING_KEY_GRACE_PERIOD_DAYS and no longer current - any
 * token still bearing that kid at that point simply fails verification,
 * same as it would after any other key loss.
 *
 * Step 14E: encryptedPrivateKey (V17 renamed this from private_key_pem) is
 * AES-256-GCM ciphertext, not a plain PEM - see SecretEncryptionService and
 * SigningKeyServiceImpl's encrypt/decrypt calls. Decrypted, it's the same
 * Base64(PEM) format the pre-14D app.authorization-server.signing-key-pem
 * env var used - chosen so the very first row this table ever gets can be
 * a byte-for-byte import of an existing deployment's env var key, without
 * invalidating every outstanding token on the upgrade that introduces this
 * table.
 */
@Entity
@Table(name = "signing_key")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class SigningKey {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 32)
    private String kid;

    @Column(name = "encrypted_private_key", nullable = false, columnDefinition = "TEXT")
    private String encryptedPrivateKey;

    @Column(name = "is_current", nullable = false)
    private boolean current;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private SigningKeyStatus status;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "retired_at")
    private LocalDateTime retiredAt;
}
