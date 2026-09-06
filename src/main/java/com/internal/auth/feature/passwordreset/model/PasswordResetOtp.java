package com.internal.auth.feature.passwordreset.model;

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
 * Represents a single password-reset OTP request lifecycle for a user.
 * The raw OTP is never persisted — only a secure hash of it, consistent
 * with how the rest of the application avoids storing sensitive secrets
 * in plaintext (see User.password, which is BCrypt-hashed).
 *
 * clientApplicationId (multi-tenant redesign, OTP/token flows step - see
 * V9 migration): phoneNumber alone is no longer a safe lookup key once the
 * same phone number can belong to accounts in different client
 * applications - PasswordResetOtpRepository's
 * findTopByPhoneNumberAndClientApplicationIdAndStatusOrderByCreatedAtDesc
 * scopes by both. Set by the caller alongside userId (OtpResetEngine's
 * populateNewOtp only fills the fields common to every ResettableOtp -
 * this one is caller-set, same reasoning as userId already was).
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "password_reset_otps")
public class PasswordResetOtp implements ResettableOtp {

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
    @Column(nullable = false)
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