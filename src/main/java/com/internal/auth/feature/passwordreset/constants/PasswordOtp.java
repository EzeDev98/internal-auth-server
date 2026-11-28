package com.internal.auth.feature.passwordreset.constants;

import lombok.Getter;
import lombok.Setter;

/** OTP settings for the password reset flow. */
@Getter
@Setter
public class PasswordOtp {
    private int length = 6;
    private int expirationMinutes = 5;
    private int maxAttempts = 5;
    private int resendCooldownSeconds = 60;
}
