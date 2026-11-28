package com.internal.auth.feature.identity.service;

import com.internal.auth.feature.identity.dto.response.ActivationResponse;
import com.internal.auth.feature.identity.model.User;

/** Operations for email-based account activation. */
public interface EmailVerificationService {
    void sendVerificationEmail(User user);

    ActivationResponse activate(String rawToken);

    ActivationResponse resendVerification(String email, Long clientApplicationId);
}
