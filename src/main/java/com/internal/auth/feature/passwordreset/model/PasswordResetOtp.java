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

/** OTP issued for a password reset request. */
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

    @Column(name = "phone_number")
    private String phoneNumber;

    @Column(name = "email")
    private String email;

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
