package com.internal.auth.feature.passwordreset.service;


import com.internal.auth.common.reset.dto.VerifyOtpRequest;
import com.internal.auth.common.reset.dto.VerifyOtpResponse;
import com.internal.auth.feature.passwordreset.dto.request.CompletePasswordResetRequest;
import com.internal.auth.feature.passwordreset.dto.request.PasswordResetRequest;
import com.internal.auth.feature.passwordreset.dto.request.EmailPasswordResetRequest;
import com.internal.auth.feature.passwordreset.dto.request.EmailVerifyOtpRequest;
import com.internal.auth.feature.passwordreset.dto.response.PasswordResetResponse;

public interface PasswordResetService {

    /**
     * Requests a password-reset OTP for the given phone number. Always
     * returns a generic success response, regardless of whether the phone
     * number is registered, to prevent user enumeration.
     *
     * @param clientApplicationId the calling app's resolved
     *   client_application_id (see PasswordResetController - resolved
     *   from the request's Authorization: Basic clientId:clientSecret
     *   header, multi-tenant redesign). Scopes the user lookup, the OTP
     *   lookup, and the resend-cooldown bucket, since phoneNumber alone
     *   can now belong to accounts in different apps.
     */
    PasswordResetResponse requestOtp(PasswordResetRequest request, Long clientApplicationId);

    /**
     * Verifies a submitted OTP and, on success, issues a short-lived,
     * single-use password-reset authorization token.
     *
     * @param clientApplicationId see requestOtp's Javadoc - scopes the OTP
     *   lookup the same way.
     */
    VerifyOtpResponse verifyOtp(VerifyOtpRequest request, Long clientApplicationId);

    /**
     * Completes the password reset using a valid reset token, updating the
     * password in both Keycloak and the local mirrored hash, then
     * invalidating all active sessions for the user.
     */
    PasswordResetResponse completeReset(CompletePasswordResetRequest request);

    /** Email counterpart of {@link #requestOtp}: sends the reset code by email. Always answers generically. */
    PasswordResetResponse requestEmailOtp(EmailPasswordResetRequest request, Long clientApplicationId);

    /** Email counterpart of {@link #verifyOtp}: exchanges the emailed code for a reset token. */
    VerifyOtpResponse verifyEmailOtp(EmailVerifyOtpRequest request, Long clientApplicationId);
}
