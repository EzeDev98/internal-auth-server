package com.internal.auth.feature.identity.repository;

import com.internal.auth.feature.identity.model.PhoneVerificationOtp;
import com.internal.auth.common.reset.ResetStatus;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/** Repository for phone verification OTPs. */
public interface PhoneVerificationOtpRepository extends JpaRepository<PhoneVerificationOtp, Long> {
    Optional<PhoneVerificationOtp> findTopByPhoneNumberAndClientApplicationIdAndStatusOrderByCreatedAtDesc(
            String phoneNumber, Long clientApplicationId, ResetStatus status);

    long deleteAllByClientApplicationId(Long clientApplicationId);
}
