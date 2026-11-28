package com.internal.auth.feature.passwordreset.config;

import com.internal.auth.feature.passwordreset.constants.PasswordOtp;
import com.internal.auth.feature.passwordreset.constants.PasswordToken;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/** Password reset settings bound from configuration properties. */
@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "password-reset")
public class PasswordResetProperties {
    private PasswordOtp otp = new PasswordOtp();
    private PasswordToken token = new PasswordToken();
}
