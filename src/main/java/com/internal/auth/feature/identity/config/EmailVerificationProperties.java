package com.internal.auth.feature.identity.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Typed configuration for Step 10C, backed by "email-verification.*"
 * properties - same pattern as PasswordResetProperties. Defaults are set
 * directly on the fields (rather than left unset) so this doesn't join the
 * class of Stage-1-flagged "silently does nothing because nothing configured
 * a default" gaps (the OTP-delivery default-disabled issue, §2.2 of the
 * assessment) - a fresh checkout works out of the box with a 24-hour token
 * lifetime and a 60-second resend cooldown even before anyone touches
 * application.properties.
 */
@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "email-verification")
public class EmailVerificationProperties {
    private int tokenExpirationMinutes = 1440;
    private int resendCooldownSeconds = 60;
}
