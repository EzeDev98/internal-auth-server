package com.internal.auth.feature.identity.repository;

import com.internal.auth.feature.identity.model.PhoneVerificationOtp;
import com.internal.auth.common.reset.ResetStatus;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/**
 * Unlike LoginMfaOtpRepository/PasswordResetOtpRepository, there's no
 * unscoped-by-phone-number-alone finder to migrate away from later -
 * client_application_id was part of PhoneVerificationOtp from its first
 * version.
 */
public interface PhoneVerificationOtpRepository extends JpaRepository<PhoneVerificationOtp, Long> {
    Optional<PhoneVerificationOtp> findTopByPhoneNumberAndClientApplicationIdAndStatusOrderByCreatedAtDesc(
            String phoneNumber, Long clientApplicationId, ResetStatus status);

    /** Backs TenantDataWipeService. */
    long deleteAllByClientApplicationId(Long clientApplicationId);
}
