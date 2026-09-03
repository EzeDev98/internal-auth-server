package com.internal.auth.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Tunable OTP settings, bound from app.otp.* properties. Add to
 * application.properties (or per-profile files) to override the defaults
 * below:
 *
 * <pre>
 * app.otp.length=6
 * app.otp.expiry-minutes=10
 * app.otp.max-attempts=5
 * app.otp.resend-cooldown-seconds=60
 * </pre>
 */
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