package com.internal.auth.feature.identity.service;

import com.internal.auth.feature.identity.dto.response.ActivationResponse;
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
     *
     * @param clientApplicationId the calling app's resolved
     *   client_application_id (see EmailVerificationController - resolved
     *   from the request's Authorization: Basic clientId:clientSecret
     *   header, multi-tenant redesign). Scopes the user lookup and the
     *   resend-cooldown bucket, since email alone can now belong to
     *   accounts in different apps. activate()/sendVerificationEmail() are
     *   untouched - both resolve via token_hash or an already-known User,
     *   never an ambiguous phone/email lookup.
     */
    ActivationResponse resendVerification(String email, Long clientApplicationId);
}
