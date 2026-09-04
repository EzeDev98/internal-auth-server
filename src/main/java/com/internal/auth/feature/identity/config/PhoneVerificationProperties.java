package com.internal.auth.feature.identity.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Typed configuration for the phone-verification OTP flow, backed by
 * "phone-verification.*" properties - same pattern as
 * EmailVerificationProperties/LoginMfaProperties. Defaults are set
 * directly on the fields so this works with no application.properties
 * changes required.
 */
@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "phone-verification")
public class PhoneVerificationProperties {
    private int otpLength = 6;
    private int otpExpirationMinutes = 10;
    private int maxAttempts = 5;
    private int resendCooldownSeconds = 60;
}
