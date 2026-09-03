package com.internal.auth.feature.passwordreset.repository;

import com.internal.auth.feature.passwordreset.enums.PasswordResetStatus;
import com.internal.auth.feature.passwordreset.model.PasswordResetOtp;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/**
 * Multi-tenant redesign, OTP/token flows step: findTopByPhoneNumberAndStatusOrderByCreatedAtDesc
 * is UNSCOPED and unsafe the moment two different client applications have
 * an active OTP for the same phone number at once - kept temporarily
 * because PasswordResetServiceImpl hasn't been migrated to the
 * ...AndClientApplicationId... variant below yet (that's the next step).
 * Delete once that migration lands.
 */
public interface PasswordResetOtpRepository extends JpaRepository<PasswordResetOtp, Long> {
    Optional<PasswordResetOtp> findTopByPhoneNumberAndStatusOrderByCreatedAtDesc(String phoneNumber, PasswordResetStatus status);
    Optional<PasswordResetOtp> findTopByPhoneNumberAndClientApplicationIdAndStatusOrderByCreatedAtDesc(String phoneNumber, Long clientApplicationId, PasswordResetStatus status);
}