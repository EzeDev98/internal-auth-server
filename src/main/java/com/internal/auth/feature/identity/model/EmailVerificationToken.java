package com.internal.auth.feature.identity.model;

import com.internal.auth.common.reset.ResettableToken;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

/**
 * Step 10C - a short-lived, single-use token proving control of the email
 * address on a User row. Mirrors PasswordResetToken's shape almost exactly
 * (same ResettableToken interface, same hash-only storage, same
 * single-use/expiry semantics) since it's the same kind of credential doing
 * a different job: this one authorizes exactly one "mark this email
 * verified" call, nothing else, and is never accepted by any other endpoint.
 *
 * Implements ResettableToken to plug directly into OtpResetEngine's
 * existing populateNewToken/assertUsable/markUsed methods - confirmed
 * generic (not hardcoded to password reset) rather than re-deriving the
 * same expiry/single-use logic a second time.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "email_verification_tokens")
public class EmailVerificationToken implements ResettableToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "token_hash", nullable = false, unique = true)
    private String tokenHash;

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    @Column(name = "used", nullable = false)
    private boolean used;

    @CreationTimestamp
    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name = "used_at")
    private LocalDateTime usedAt;
}
