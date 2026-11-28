package com.internal.auth.feature.identity.service;

import com.internal.auth.common.reset.dto.VerifyOtpRequest;
import com.internal.auth.feature.identity.dto.response.ActivationResponse;
import com.internal.auth.feature.identity.model.User;

/** Operations for phone number verification. */
public interface PhoneVerificationService {
    void sendVerificationOtp(User user);

    ActivationResponse verify(VerifyOtpRequest request, Long clientApplicationId);

    ActivationResponse resendVerification(String phoneNumber, Long clientApplicationId);
}
