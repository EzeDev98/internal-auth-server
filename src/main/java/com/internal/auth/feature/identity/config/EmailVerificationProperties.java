package com.internal.auth.feature.identity.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/** Email verification settings bound from email-verification properties. */
@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "email-verification")
public class EmailVerificationProperties {
    private int tokenExpirationMinutes = 1440;
    private int resendCooldownSeconds = 60;
}
