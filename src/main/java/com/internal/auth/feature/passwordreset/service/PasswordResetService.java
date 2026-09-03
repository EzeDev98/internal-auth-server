package com.internal.auth.feature.passwordreset.service;


import com.internal.auth.common.reset.dto.VerifyOtpRequest;
import com.internal.auth.common.reset.dto.VerifyOtpResponse;
import com.internal.auth.feature.passwordreset.dto.CompletePasswordResetRequest;
import com.internal.auth.feature.passwordreset.dto.PasswordResetRequestDto;
import com.internal.auth.feature.passwordreset.dto.PasswordResetResponse;

public interface PasswordResetService {

    /**
     * Requests a password-reset OTP for the given phone number. Always
     * returns a generic success response, regardless of whether the phone
     * number is registered, to prevent user enumeration.
     */
    PasswordResetResponse requestOtp(PasswordResetRequestDto request);

    /**
     * Verifies a submitted OTP and, on success, issues a short-lived,
     * single-use password-reset authorization token.
     */
    VerifyOtpResponse verifyOtp(VerifyOtpRequest request);

    /**
     * Completes the password reset using a valid reset token, updating the
     * password in both Keycloak and the local mirrored hash, then
     * invalidating all active sessions for the user.
     */
    PasswordResetResponse completeReset(CompletePasswordResetRequest request);
}