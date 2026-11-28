package com.internal.auth.feature.passwordreset.repository;

import com.internal.auth.common.reset.ResetStatus;
import com.internal.auth.feature.passwordreset.model.PasswordResetOtp;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/** Repository for password reset OTPs. */
public interface PasswordResetOtpRepository extends JpaRepository<PasswordResetOtp, Long> {
    Optional<PasswordResetOtp> findTopByPhoneNumberAndStatusOrderByCreatedAtDesc(String phoneNumber, ResetStatus status);
    Optional<PasswordResetOtp> findTopByPhoneNumberAndClientApplicationIdAndStatusOrderByCreatedAtDesc(String phoneNumber, Long clientApplicationId, ResetStatus status);
    Optional<PasswordResetOtp> findTopByEmailAndClientApplicationIdAndStatusOrderByCreatedAtDesc(String email, Long clientApplicationId, ResetStatus status);

    long deleteAllByClientApplicationId(Long clientApplicationId);
}
