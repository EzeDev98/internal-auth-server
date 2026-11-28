package com.internal.auth.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/** Tunable OTP settings bound from app.otp properties. */
@Component
@ConfigurationProperties(prefix = "app.otp")
@Getter
@Setter
public class OtpProperties {

    private int length = 6;
    private int expiryMinutes = 10;
    private int maxAttempts = 5;
    private int resendCooldownSeconds = 60;
}
