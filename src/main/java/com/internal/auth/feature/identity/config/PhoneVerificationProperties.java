package com.internal.auth.feature.identity.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/** Phone verification OTP settings bound from phone-verification properties. */
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
