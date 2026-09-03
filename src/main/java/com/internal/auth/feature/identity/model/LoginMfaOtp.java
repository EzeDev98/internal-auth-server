package com.internal.auth.feature.identity.model;

import com.internal.auth.common.reset.ResettableOtp;
import com.internal.auth.feature.passwordreset.enums.PasswordResetStatus;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

/**
 * Step 11E - the OTP sent as a login step-up for accounts with
 * mfaEnabled=true. Mirrors PasswordResetOtp field-for-field since it plugs
 * into the same generic OtpResetEngine via ResettableOtp. Unlike password
 * reset, there's no matching *Token entity - once the code is verified
 * there's nothing further to collect from the user, so login completes
 * directly on a successful verify() rather than needing an intermediate
 * ResettableToken phase.
 *
 * status uses PasswordResetStatus (ACTIVE/VERIFIED/EXPIRED/INVALIDATED)
 * only because ResettableOtp's contract is typed to it - a generic OTP
 * lifecycle state, not something specific to password reset, despite the
 * enum's name.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "login_mfa_otps")
public class LoginMfaOtp implements ResettableOtp {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "phone_number", nullable = false)
    private String phoneNumber;

    @Column(name = "otp_hash", nullable = false)
    private String otpHash;

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    @Column(name = "attempt_count", nullable = false)
    private int attemptCount;

    @Column(name = "max_attempts", nullable = false)
    private int maxAttempts;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    private PasswordResetStatus status;

    @CreationTimestamp
    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name = "verified_at")
    private LocalDateTime verifiedAt;

    @Column(name = "invalidated_at")
    private LocalDateTime invalidatedAt;

    @Column(name = "last_sent_at")
    private LocalDateTime lastSentAt;
}
