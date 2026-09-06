package com.internal.auth.feature.identity.model;

import com.internal.auth.common.reset.ResettableOtp;
import com.internal.auth.common.reset.ResetStatus;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

/**
 * Self-service phone verification (fixes the previously-permanent
 * phone-only-account login gate - see User's class Javadoc). Mirrors
 * LoginMfaOtp/PasswordResetOtp field-for-field via ResettableOtp. Like
 * EmailVerificationToken, no separate follow-up token exists - a
 * successful verify() sets phoneVerified=true directly
 * (PhoneVerificationServiceImpl#verify).
 *
 * clientApplicationId is required from this entity's first version -
 * unlike login_mfa_otps/password_reset_otps, which needed a V9 follow-up
 * migration to add it after the fact.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "phone_verification_otps")
public class PhoneVerificationOtp implements ResettableOtp {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "client_application_id", nullable = false)
    private Long clientApplicationId;

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
    private ResetStatus status;

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
