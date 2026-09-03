package com.internal.auth.feature.identity.service;

import com.internal.auth.feature.identity.dto.ActivationResponse;
import com.internal.auth.feature.identity.model.User;

public interface EmailVerificationService {

    /**
     * Issues a new verification token for the given user and sends it.
     * No-op if the user has no email address on file. Delivery failures
     * are swallowed (logged, not thrown) so a provider outage never blocks
     * registration or resend from otherwise succeeding.
     */
    void sendVerificationEmail(User user);

    ActivationResponse activate(String rawToken);

    /**
     * Enumeration-resistant: always returns the same generic response
     * regardless of whether the email is registered, already verified, or
     * unknown - mirrors PasswordResetServiceImpl#requestOtp's approach.
     */
    ActivationResponse resendVerification(String email);
}
