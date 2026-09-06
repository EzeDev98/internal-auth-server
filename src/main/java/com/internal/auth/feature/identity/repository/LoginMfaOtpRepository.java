package com.internal.auth.feature.identity.repository;

import com.internal.auth.feature.identity.model.LoginMfaOtp;
import com.internal.auth.common.reset.ResetStatus;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/**
 * Multi-tenant redesign, OTP/token flows step: findTopByPhoneNumberAndStatusOrderByCreatedAtDesc
 * is UNSCOPED and unsafe the moment two different client applications have
 * an active login-MFA OTP for the same phone number at once - kept
 * temporarily because LoginServiceImpl hasn't been migrated to the
 * ...AndClientApplicationId... variant below yet (that's the next step).
 * Delete once that migration lands.
 */
public interface LoginMfaOtpRepository extends JpaRepository<LoginMfaOtp, Long> {
    Optional<LoginMfaOtp> findTopByPhoneNumberAndStatusOrderByCreatedAtDesc(String phoneNumber, ResetStatus status);
    Optional<LoginMfaOtp> findTopByPhoneNumberAndClientApplicationIdAndStatusOrderByCreatedAtDesc(String phoneNumber, Long clientApplicationId, ResetStatus status);
}
