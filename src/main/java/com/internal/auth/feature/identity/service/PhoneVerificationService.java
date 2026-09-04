package com.internal.auth.feature.identity.service;

import com.internal.auth.common.reset.dto.VerifyOtpRequest;
import com.internal.auth.feature.identity.dto.ActivationResponse;
import com.internal.auth.feature.identity.model.User;

public interface PhoneVerificationService {

    /**
     * Issues and sends a new phone-verification OTP for the given user.
     * No-op if the user has no phone number, or it's already verified.
     * Delivery failures are swallowed (logged, not thrown), mirroring
     * EmailVerificationService#sendVerificationEmail.
     */
    void sendVerificationOtp(User user);

    /**
     * Verifies the OTP and, on success, sets User.phoneVerified=true -
     * closing the login gate described on User's class Javadoc.
     *
     * @param clientApplicationId resolved by PhoneVerificationController
     *   from the Authorization: Basic clientId:clientSecret header,
     *   scoping the OTP lookup the same way
     *   PasswordResetServiceImpl#verifyOtp scopes its own.
     */
    ActivationResponse verify(VerifyOtpRequest request, Long clientApplicationId);

    /**
     * Enumeration-resistant: always returns the same generic response
     * regardless of whether the phone number is registered, already
     * verified, or unknown - mirrors EmailVerificationService#resendVerification.
     */
    ActivationResponse resendVerification(String phoneNumber, Long clientApplicationId);
}
