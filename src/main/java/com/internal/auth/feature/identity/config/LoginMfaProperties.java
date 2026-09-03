package com.internal.auth.feature.identity.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Step 11E. Typed configuration for the login-MFA OTP step-up, backed by
 * "login-mfa.*" properties - same pattern as PasswordResetProperties.
 * Defaults are set directly on the fields so this works without requiring
 * application.properties changes, same reasoning as EmailVerificationProperties
 * (Step 10C).
 */
@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "login-mfa")
public class LoginMfaProperties {
    private int otpLength = 6;
    private int otpExpirationMinutes = 5;
    private int maxAttempts = 3;
    private int resendCooldownSeconds = 60;
}
