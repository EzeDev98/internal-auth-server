package com.internal.auth.feature.passwordreset.service;


import com.internal.auth.common.reset.dto.VerifyOtpRequest;
import com.internal.auth.common.reset.dto.VerifyOtpResponse;
import com.internal.auth.feature.passwordreset.dto.request.CompletePasswordResetRequest;
import com.internal.auth.feature.passwordreset.dto.request.PasswordResetRequest;
import com.internal.auth.feature.passwordreset.dto.request.EmailPasswordResetRequest;
import com.internal.auth.feature.passwordreset.dto.request.EmailVerifyOtpRequest;
import com.internal.auth.feature.passwordreset.dto.response.PasswordResetResponse;

/** Operations for the password reset flow. */
public interface PasswordResetService {
    PasswordResetResponse requestOtp(PasswordResetRequest request, Long clientApplicationId);

    VerifyOtpResponse verifyOtp(VerifyOtpRequest request, Long clientApplicationId);

    PasswordResetResponse completeReset(CompletePasswordResetRequest request);

    PasswordResetResponse requestEmailOtp(EmailPasswordResetRequest request, Long clientApplicationId);

    VerifyOtpResponse verifyEmailOtp(EmailVerifyOtpRequest request, Long clientApplicationId);
}
